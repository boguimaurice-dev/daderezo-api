"""Request-scoped audit identity (propagated into FastAPI worker threads)."""
from contextvars import ContextVar

identity = ContextVar("audit_identity", default=None)


def current():
    return identity.get() or {"org_slug": "system", "actor": "system", "request_id": ""}
