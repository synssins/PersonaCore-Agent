"""Optional OpenTelemetry OTLP tracing — no-op when opentelemetry is absent.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Do NOT add opentelemetry to pyproject.toml. This module activates only when
the package is already installed in the environment (opt-in).
"""

from __future__ import annotations

import logging
from typing import Self

log = logging.getLogger(__name__)

try:
    from opentelemetry import trace as _otel_trace  # type: ignore[import]
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import]
        OTLPSpanExporter as _OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource as _Resource  # type: ignore[import]
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider  # type: ignore[import]
    from opentelemetry.sdk.trace.export import (  # type: ignore[import]
        BatchSpanProcessor as _BatchSpanProcessor,
    )

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    _otel_trace = None  # type: ignore[assignment]


def configure(
    service_name: str = "workstation-agent",
    otlp_endpoint: str = "http://localhost:4317",
) -> None:
    """Configure OTLP tracing if opentelemetry is installed; otherwise no-op.

    Args:
        service_name: Resource attribute for the service name.
        otlp_endpoint: gRPC endpoint for the OTLP collector.
    """
    if not _OTEL_AVAILABLE or _otel_trace is None:
        log.debug("opentelemetry not installed; tracing is a no-op")
        return

    resource = _Resource.create({"service.name": service_name})  # type: ignore[possibly-unbound]
    provider = _TracerProvider(resource=resource)  # type: ignore[possibly-unbound]
    exporter = _OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)  # type: ignore[call-arg, possibly-unbound]
    provider.add_span_processor(_BatchSpanProcessor(exporter))  # type: ignore[possibly-unbound]
    _otel_trace.set_tracer_provider(provider)
    log.info("OTLP tracing configured: endpoint=%s service=%s", otlp_endpoint, service_name)


def get_tracer(name: str = "workstation_agent") -> object:
    """Return an OpenTelemetry tracer (or a no-op stub if unavailable).

    Args:
        name: Instrumentation scope name.

    Returns:
        A tracer object; callers may use it with ``tracer.start_as_current_span``.
    """
    if not _OTEL_AVAILABLE or _otel_trace is None:
        return _NoopTracer()
    return _otel_trace.get_tracer(name)


class _NoopSpan:
    """Minimal span stub used when opentelemetry is absent."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def set_attribute(self, _key: str, _value: object) -> None:
        pass

    def record_exception(self, _exc: BaseException) -> None:
        pass


class _NoopTracer:
    """Minimal tracer stub used when opentelemetry is absent."""

    def start_as_current_span(self, name: str, **_kwargs: object) -> _NoopSpan:  # noqa: ARG002
        """Return a no-op span context manager."""
        return _NoopSpan()
