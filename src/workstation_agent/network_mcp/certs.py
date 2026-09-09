"""The self-signed certificate the network MCP endpoint presents (contract §3).

ECDSA P-256, ten years, SAN = the workstation's hostname and its LAN IP.
``cryptography>=41.0`` was already declared in ``pyproject.toml`` and unused, so
this needs no new dependency.

**Persisted and reused across restarts, and that is the load-bearing property.**
The core does not check this certificate against the system trust store; it pins
``tls_fingerprint`` from the registration and verifies *that* (contract §3). So a
regenerated certificate is not a fresh start — it is a new fingerprint, and the
core's connection fails with "the certificate at <url> is sha256:… but the
registration pins sha256:…" until a human regenerates and reinstalls the
registration. Contract §11 item 8 requires that starting the Agent simply brings
the endpoint back.

Consequences of that, both deliberate:

* A certificate is regenerated **only** when there is none, when the stored one
  cannot be parsed, when it has expired, or when the operator explicitly asks.
  Never because the machine's IP changed.
* If a chosen address is not in the certificate's SAN list this module logs a
  warning and carries on: it will not rotate a fingerprint the core has pinned
  on its own initiative. Refusing to *bind* that address is
  :mod:`~workstation_agent.network_mcp.listeners`' job, which is where the
  operator can be told which address and offered
  :func:`ensure_certificate` with ``regenerate=True`` explicitly, with the
  fingerprint consequence stated.

The SAN covers the whole chosen set, not just one address — see ``bind_hosts``
on :func:`ensure_certificate`. An address bound but absent from the SAN is one
where the core's pin succeeds and a hostname-verifying client is rejected, with
nothing on either side saying why.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from workstation_agent.network_mcp.credentials import DEFAULT_STATE_DIR, _harden

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Sequence
    from pathlib import Path

log = logging.getLogger(__name__)

_CERT_FILE_NAME: Final = "server.crt"
_KEY_FILE_NAME: Final = "server.key"
_VALIDITY_DAYS: Final = 3650
_CLOCK_SKEW = dt.timedelta(days=1)


@dataclass(frozen=True)
class CertificateInfo:
    """Everything the server and the UI need about the endpoint's certificate."""

    cert_path: Path
    key_path: Path
    fingerprint: str
    """``sha256:`` + 64 lowercase hex of the leaf certificate's DER (contract §3)."""
    sans: tuple[str, ...]
    """The SAN entries, as text: DNS names then IP addresses."""
    not_valid_after: dt.datetime
    generated: bool
    """True if this call created the certificate rather than reusing a stored one."""


def fingerprint_of(cert: x509.Certificate) -> str:
    """Return the contract §3 fingerprint string for *cert*."""
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


def sans_of_file(cert_path: Path) -> tuple[str, ...]:
    """Parse the certificate at *cert_path* and return its SAN entries.

    The authority for "what names does this endpoint claim to be". Read from the
    file rather than handed around as a list, because this is the same file
    ``uvicorn`` is given as ``ssl_certfile`` and therefore the certificate that
    is actually presented on the wire — a snapshot taken earlier could have gone
    stale, and a list passed as an argument can be anything at all.

    Raises:
        OSError: if the file cannot be read.
        ValueError: if it is not a parseable PEM certificate.

    Deliberately *not* guarded. Every caller uses this to decide whether it is
    safe to put a listener on an address; a failure that returned ``()`` instead
    would read as "this certificate covers nothing", and a failure that returned
    "assume covered" would open exactly the hole the check exists to close.
    Neither is an answer, so it raises.
    """
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return _sans_of(cert)


def _expiry_utc(cert: x509.Certificate) -> dt.datetime:
    """Return *cert*'s expiry as a timezone-aware UTC datetime.

    ``cryptography`` 41 (the pinned range in ``pyproject.toml``) exposes only the
    naive ``not_valid_after``, documented as UTC; 42 added ``not_valid_after_utc``
    and deprecated the naive one. Reading whichever exists keeps this correct
    across the pin being widened later, and keeps every comparison in this module
    timezone-aware so a naive/aware mix cannot silently misjudge an expiry.
    """
    aware = getattr(cert, "not_valid_after_utc", None)
    if aware is not None:
        return aware
    return cert.not_valid_after.replace(tzinfo=dt.UTC)


def _sans_of(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:  # pragma: no cover — we always add one
        return ()
    names: list[str] = list(ext.value.get_values_for_type(x509.DNSName))
    names.extend(str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress))
    return tuple(names)


def local_identities(  # noqa: C901 — one guarded lookup per source; splitting hides them
    extra_host: str | None = None,
    *,
    extra_hosts: Sequence[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Discover this workstation's DNS names and IP addresses for the SAN.

    Every lookup is guarded: a machine with no DNS, no network, or a hostname
    that does not resolve must still get a certificate. Worst case the SAN is
    ``localhost`` and ``127.0.0.1``, which is enough for a pinning client.

    **This is the single source for both the SAN and the list of addresses the
    UI offers**, which is what makes "an address you can select" and "an address
    the certificate covers" the same set by construction rather than by two
    lists someone has to keep in step.

    Args:
        extra_host: The interface the operator chose to bind, if known. Included
            so the common case (bind to the LAN IP) is covered by the SAN even
            when name resolution is unhelpful.
        extra_hosts: Every interface the operator chose, when the endpoint binds
            a set rather than one address. Each is covered by the SAN for the
            same reason *extra_host* is — an address bound but not covered is an
            address a hostname-verifying client rejects.

    Returns:
        ``(dns_names, ip_addresses)``, each de-duplicated and order-stable.
    """
    dns_names: list[str] = []
    ips: list[str] = []

    def _add_host(value: str | None) -> None:
        if not value:
            return
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if value not in dns_names:
                dns_names.append(value)
        else:
            if value not in ips:
                ips.append(value)

    try:
        hostname = socket.gethostname()
    except OSError:  # pragma: no cover — gethostname does not realistically fail
        hostname = ""
    _add_host(hostname)
    if hostname:
        with contextlib.suppress(OSError):  # pragma: no cover
            _add_host(socket.getfqdn(hostname))
        try:
            for addr in socket.gethostbyname_ex(hostname)[2]:
                _add_host(addr)
        except OSError:
            log.debug("hostname %r does not resolve; SAN will omit its addresses", hostname)

    # The primary outbound interface, found without sending a packet: connecting
    # a UDP socket only sets the destination and picks a source address.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1, RFC 5737 — never routed
        _add_host(sock.getsockname()[0])
    except OSError:
        log.debug("no outbound interface; SAN will omit the primary LAN address")
    finally:
        sock.close()

    _add_host(extra_host)
    for host in extra_hosts or ():
        _add_host(host.strip().strip("[]") or None)
    _add_host("localhost")
    _add_host("127.0.0.1")
    return dns_names, ips


def _build_certificate(
    dns_names: list[str],
    ips: list[str],
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    common_name = dns_names[0] if dns_names else "workstation-agent"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PersonaCore-Agent"),
    ])
    san_entries: list[x509.GeneralName] = [x509.DNSName(n) for n in dns_names]
    san_entries.extend(x509.IPAddress(ipaddress.ip_address(i)) for i in ips)

    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + dt.timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _load(cert_path: Path, key_path: Path) -> x509.Certificate | None:
    """Load and sanity-check a stored certificate; None means "unusable"."""
    if not cert_path.exists() or not key_path.exists():
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        log.warning("stored network MCP certificate at %s is unusable (%s)", cert_path, exc)
        return None
    if _expiry_utc(cert) <= dt.datetime.now(dt.UTC):
        log.warning(
            "stored network MCP certificate expired on %s; a new one will be generated "
            "and PersonaCore's pinned tls_fingerprint must be updated",
            _expiry_utc(cert).isoformat(),
        )
        return None
    return cert


def ensure_certificate(
    state_dir: Path | None = None,
    *,
    bind_host: str | None = None,
    bind_hosts: Sequence[str] | None = None,
    regenerate: bool = False,
) -> CertificateInfo:
    """Return the endpoint's certificate, generating it only when it must.

    Args:
        state_dir: Directory holding ``server.crt`` / ``server.key``. Defaults to
            :data:`~workstation_agent.network_mcp.credentials.DEFAULT_STATE_DIR`.
        bind_host: The interface the endpoint will bind, included in the SAN when
            a certificate is generated and warned about when a stored certificate
            does not cover it.
        bind_hosts: Every interface the endpoint will bind, when it binds a set.
            Supersedes *bind_host* when both are given. The SAN must cover the
            whole set: an address bound but absent from the SAN is one where
            pinning succeeds and hostname verification fails, which is the
            failure this argument exists to make impossible.
        regenerate: Force a new certificate. **This changes the fingerprint** and
            therefore breaks the core's pin until the registration is
            regenerated and reinstalled; it exists for the UI's explicit
            "rotate certificate" action only.

    Returns:
        A :class:`CertificateInfo`.
    """
    directory = state_dir if state_dir is not None else DEFAULT_STATE_DIR
    cert_path = directory / _CERT_FILE_NAME
    key_path = directory / _KEY_FILE_NAME

    wanted: list[str] = [h for h in (bind_hosts or ()) if h and h.strip()]
    if not wanted and bind_host:
        wanted = [bind_host]

    stored = None if regenerate else _load(cert_path, key_path)
    if stored is not None:
        sans = _sans_of(stored)
        # The same comparison the endpoint binds by, so this warning and that
        # refusal cannot disagree. String equality would report ``[::1]`` as
        # uncovered by a SAN carrying ``::1`` and send the operator to rotate a
        # fingerprint that was fine.
        from workstation_agent.registration_export import san_covers  # noqa: PLC0415

        uncovered = [h for h in wanted if not san_covers(h, sans)]
        if uncovered:
            # Still only a warning here, and still deliberately so: this
            # function must never silently rotate a fingerprint the core has
            # pinned. Refusing to *bind* an uncovered address is
            # ``network_mcp/server.py``'s job, which is where the operator can
            # be told which address and offered the rotation explicitly.
            log.warning(
                "the stored certificate's SAN (%s) does not cover %s. "
                "Not regenerating: a new certificate would change the pinned fingerprint "
                "and the core verifies the pin, not the SAN.",
                ", ".join(sans) or "empty",
                ", ".join(repr(h) for h in uncovered),
            )
        return CertificateInfo(
            cert_path=cert_path,
            key_path=key_path,
            fingerprint=fingerprint_of(stored),
            sans=sans,
            not_valid_after=_expiry_utc(stored),
            generated=False,
        )

    dns_names, ips = local_identities(extra_hosts=wanted)
    cert, key = _build_certificate(dns_names, ips)

    directory.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    _harden(key_path)

    info = CertificateInfo(
        cert_path=cert_path,
        key_path=key_path,
        fingerprint=fingerprint_of(cert),
        sans=_sans_of(cert),
        not_valid_after=_expiry_utc(cert),
        generated=True,
    )
    log.info(
        "generated network MCP certificate %s (SAN: %s). PersonaCore's registration must "
        "pin tls_fingerprint = %r.",
        cert_path,
        ", ".join(info.sans),
        info.fingerprint,
    )
    return info
