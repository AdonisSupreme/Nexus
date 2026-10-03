"""Reuse authentication only inside one already-authorized HTTP request.

Nothing is cached between requests or WebSocket events, so revocations remain
effective on the next operation. ContextVar isolates concurrent ASGI requests.
"""
from contextvars import ContextVar

request_identity = ContextVar('sentinel_request_identity', default=None)


def authenticated_user(authorization):
    identity = request_identity.get()
    return identity[1] if identity and identity[0] == authorization else None
