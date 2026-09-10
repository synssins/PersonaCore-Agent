"""Token and certificate persistence.

Contract §11 item 8: stopping and starting the Agent must bring the endpoint back
without anyone touching PersonaCore. That means the token *and* the certificate
survive a restart unchanged, because the core pins the fingerprint and holds
its own copy of the token, minted and pushed to us once at enrolment.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from workstation_agent.network_mcp import certs, credentials

# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------


def test_token_is_32_bytes_of_entropy(tmp_path):
    token = credentials.ensure_token(tmp_path)
    assert len(token) == 64, "32 bytes rendered as hex"
    assert bytes.fromhex(token)
    assert token.isascii(), "must be safe to compare as bytes without decoding"


def test_token_is_reused_across_restarts(tmp_path):
    first = credentials.ensure_token(tmp_path)
    for _ in range(3):
        assert credentials.ensure_token(tmp_path) == first


def test_two_workstations_get_different_tokens(tmp_path):
    a = credentials.ensure_token(tmp_path / "a")
    b = credentials.ensure_token(tmp_path / "b")
    assert a != b


def test_rotation_replaces_the_token_and_persists(tmp_path):
    first = credentials.ensure_token(tmp_path)
    second = credentials.ensure_token(tmp_path, rotate=True)
    assert second != first
    assert credentials.ensure_token(tmp_path) == second


@pytest.mark.parametrize("corrupt", [b"", b"   \n", b"\xff\xfe\x00"])
def test_an_unreadable_or_empty_token_file_is_replaced(tmp_path, corrupt):
    credentials.ensure_token(tmp_path)
    (tmp_path / "token").write_bytes(corrupt)
    replacement = credentials.ensure_token(tmp_path)
    assert len(replacement) == 64
    assert credentials.ensure_token(tmp_path) == replacement


def test_missing_harden_file_is_a_warning_not_a_failure(tmp_path, caplog):
    """``security.dpapi`` has no ``harden_file`` today; that must not stop startup."""
    with caplog.at_level("WARNING"):
        token = credentials.ensure_token(tmp_path)
    assert len(token) == 64


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------


def _load(tmp_path) -> x509.Certificate:
    return x509.load_pem_x509_certificate((tmp_path / "server.crt").read_bytes())


def test_certificate_is_generated_on_first_run(tmp_path):
    info = certs.ensure_certificate(tmp_path)
    assert info.generated is True
    assert info.cert_path.exists()
    assert info.key_path.exists()
    assert info.fingerprint.startswith("sha256:")
    assert len(info.fingerprint) == len("sha256:") + 64


def test_certificate_and_fingerprint_survive_a_restart(tmp_path):
    """The load-bearing property: regenerating would break the core's pin."""
    first = certs.ensure_certificate(tmp_path)
    for _ in range(3):
        again = certs.ensure_certificate(tmp_path)
        assert again.generated is False
        assert again.fingerprint == first.fingerprint
        assert again.sans == first.sans


def test_fingerprint_is_the_sha256_of_the_der_leaf(tmp_path):
    """Contract §3: ``sha256:`` + hex SHA-256 of the leaf certificate in DER."""
    info = certs.ensure_certificate(tmp_path)
    cert = _load(tmp_path)
    expected = hashes.Hash(hashes.SHA256())
    expected.update(cert.public_bytes(serialization.Encoding.DER))
    assert info.fingerprint == "sha256:" + expected.finalize().hex()


def test_san_covers_the_hostname_and_an_ip(tmp_path):
    """Contract §3: SAN = its hostname and LAN IP."""
    info = certs.ensure_certificate(tmp_path)
    assert socket.gethostname() in info.sans
    ips = [s for s in info.sans if _is_ip(s)]
    assert ips, "no IP address in the SAN"
    assert "127.0.0.1" in ips


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def test_bind_host_is_included_in_the_san_when_generating(tmp_path):
    info = certs.ensure_certificate(tmp_path, bind_host="10.42.0.7")
    assert "10.42.0.7" in info.sans


def test_a_changed_bind_host_does_not_regenerate(tmp_path, caplog):
    """A new IP must never silently change the fingerprint the core pinned."""
    first = certs.ensure_certificate(tmp_path, bind_host="10.42.0.7")
    with caplog.at_level("WARNING", logger="workstation_agent.network_mcp.certs"):
        again = certs.ensure_certificate(tmp_path, bind_host="10.99.0.1")
    assert again.fingerprint == first.fingerprint
    assert again.generated is False
    assert any("Not regenerating" in r.getMessage() for r in caplog.records)


def test_explicit_regeneration_changes_the_fingerprint(tmp_path):
    first = certs.ensure_certificate(tmp_path)
    rotated = certs.ensure_certificate(tmp_path, regenerate=True)
    assert rotated.generated is True
    assert rotated.fingerprint != first.fingerprint
    assert certs.ensure_certificate(tmp_path).fingerprint == rotated.fingerprint


@pytest.mark.parametrize("victim", ["server.crt", "server.key"])
def test_a_corrupt_certificate_or_key_is_replaced(tmp_path, victim):
    certs.ensure_certificate(tmp_path)
    (tmp_path / victim).write_bytes(b"not a PEM file")
    replacement = certs.ensure_certificate(tmp_path)
    assert replacement.generated is True
    assert certs.ensure_certificate(tmp_path).generated is False


@pytest.mark.parametrize("victim", ["server.crt", "server.key"])
def test_a_missing_half_of_the_pair_is_replaced(tmp_path, victim):
    certs.ensure_certificate(tmp_path)
    (tmp_path / victim).unlink()
    assert certs.ensure_certificate(tmp_path).generated is True


def test_an_expired_certificate_is_replaced(tmp_path):
    _write_expired(tmp_path)
    info = certs.ensure_certificate(tmp_path)
    assert info.generated is True
    assert info.not_valid_after > dt.datetime.now(dt.UTC)


def _write_expired(tmp_path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old")])
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=30)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past - dt.timedelta(days=1))
        .not_valid_after(past)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("old")]), critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "server.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def test_certificate_is_valid_for_about_ten_years(tmp_path):
    """Contract §3: ten years."""
    info = certs.ensure_certificate(tmp_path)
    years = (info.not_valid_after - dt.datetime.now(dt.UTC)).days / 365.25
    assert 9.5 < years < 10.5


def test_certificate_is_a_p256_server_certificate(tmp_path):
    """Contract §3 allows RSA 2048 or ECDSA P-256; we chose P-256."""
    certs.ensure_certificate(tmp_path)
    cert = _load(tmp_path)
    public_key = cert.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert public_key.curve.name == "secp256r1"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False


def test_not_valid_before_allows_for_clock_skew(tmp_path):
    """A workstation whose clock is a few hours fast must still be trusted."""
    certs.ensure_certificate(tmp_path)
    cert = _load(tmp_path)
    before = getattr(cert, "not_valid_before_utc", None)
    if before is None:
        before = cert.not_valid_before.replace(tzinfo=dt.UTC)
    assert before < dt.datetime.now(dt.UTC) - dt.timedelta(hours=12)


def test_local_identities_never_raises_without_a_network(monkeypatch):
    """A machine with no DNS and no route must still get a usable SAN."""

    def _boom(*_args, **_kwargs):
        msg = "no network"
        raise OSError(msg)

    monkeypatch.setattr(socket, "gethostbyname_ex", _boom)
    monkeypatch.setattr(socket, "getfqdn", _boom)
    monkeypatch.setattr(socket.socket, "connect", _boom)
    dns, ips = certs.local_identities()
    assert "localhost" in dns
    assert "127.0.0.1" in ips


def test_certificate_generation_survives_a_hostless_machine(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "")
    monkeypatch.setattr(socket.socket, "connect", _raise_os)
    info = certs.ensure_certificate(tmp_path)
    assert info.generated is True
    assert "localhost" in info.sans


def _raise_os(*_args, **_kwargs):
    msg = "no route"
    raise OSError(msg)
