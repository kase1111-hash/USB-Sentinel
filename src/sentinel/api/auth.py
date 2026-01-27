"""
Authentication middleware for API security.

Supports:
- API key authentication (development/simple deployments)
- mTLS client certificate authentication (production)
- Rate limiting via token bucket algorithm
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, APIKeyQuery

logger = logging.getLogger(__name__)


# ============================================================================
# API Key Authentication
# ============================================================================


# API key can be provided via header or query parameter
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)


@dataclass
class APIKey:
    """
    API key with metadata.

    Attributes:
        key_hash: SHA-256 hash of the actual key
        name: Human-readable name for the key
        created_at: When the key was created
        expires_at: Optional expiration time
        permissions: List of allowed operations
        rate_limit: Requests per minute limit
    """

    key_hash: str
    name: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    permissions: list[str] = field(default_factory=lambda: ["read"])
    rate_limit: int = 60  # requests per minute

    def is_expired(self) -> bool:
        """Check if key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def has_permission(self, permission: str) -> bool:
        """Check if key has specific permission."""
        return permission in self.permissions or "admin" in self.permissions


def hash_api_key(key: str, salt: str | None = None) -> str:
    """
    Hash an API key for secure storage using HMAC-SHA256 with salt.

    Args:
        key: Plain text API key
        salt: Optional salt (uses key prefix if not provided for consistency)

    Returns:
        HMAC-SHA256 hash of the key with salt
    """
    # Use key prefix as salt for backward compatibility and consistency
    # This ensures the same key always produces the same hash
    if salt is None:
        salt = key[:8] if len(key) >= 8 else key
    return hmac.new(salt.encode(), key.encode(), hashlib.sha256).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.

    Returns:
        Tuple of (plain text key, key hash)
    """
    key = f"usk_{secrets.token_urlsafe(32)}"
    return key, hash_api_key(key)


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """
    Verify an API key against its hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        provided_key: Key provided by client
        stored_hash: Hash of the valid key

    Returns:
        True if key is valid
    """
    provided_hash = hash_api_key(provided_key)
    return hmac.compare_digest(provided_hash, stored_hash)


class APIKeyManager:
    """
    Manages API key storage and validation.

    In production, keys should be stored in a secure database.
    This implementation uses in-memory storage for simplicity.
    """

    def __init__(self) -> None:
        """Initialize key manager."""
        self._keys: dict[str, APIKey] = {}
        self._default_key: str | None = None

    def add_key(
        self,
        key: str,
        name: str,
        permissions: list[str] | None = None,
        expires_at: datetime | None = None,
        rate_limit: int = 60,
    ) -> None:
        """
        Add an API key.

        Args:
            key: Plain text API key
            name: Name for the key
            permissions: List of permissions
            expires_at: Optional expiration
            rate_limit: Requests per minute limit
        """
        key_hash = hash_api_key(key)
        self._keys[key_hash] = APIKey(
            key_hash=key_hash,
            name=name,
            permissions=permissions or ["read"],
            expires_at=expires_at,
            rate_limit=rate_limit,
        )

    def set_default_key(self, key: str) -> None:
        """
        Set a default API key for development.

        Args:
            key: Plain text API key to set as default
        """
        self._default_key = hash_api_key(key)
        self.add_key(key, "default", permissions=["admin"])

    def validate_key(self, key: str) -> APIKey | None:
        """
        Validate an API key.

        Args:
            key: Plain text API key

        Returns:
            APIKey object if valid, None otherwise
        """
        key_hash = hash_api_key(key)
        api_key = self._keys.get(key_hash)

        if api_key is None:
            return None

        if api_key.is_expired():
            logger.warning(f"Expired API key used: {api_key.name}")
            return None

        return api_key

    def revoke_key(self, key: str) -> bool:
        """
        Revoke an API key.

        Args:
            key: Plain text API key to revoke

        Returns:
            True if key was revoked
        """
        key_hash = hash_api_key(key)
        if key_hash in self._keys:
            del self._keys[key_hash]
            return True
        return False


# Global key manager instance
key_manager = APIKeyManager()


# ============================================================================
# Rate Limiting
# ============================================================================


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    Attributes:
        capacity: Maximum tokens in bucket
        tokens: Current token count
        fill_rate: Tokens added per second
        last_update: Last time tokens were added
    """

    capacity: int
    tokens: float = field(init=False)
    fill_rate: float = field(init=False)
    last_update: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Initialize token count and fill rate."""
        self.tokens = float(self.capacity)
        self.fill_rate = self.capacity / 60.0  # tokens per second

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were available
        """
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now


class RateLimiter:
    """
    Rate limiter using token bucket algorithm.

    Tracks request rates per client identifier (IP or API key).
    """

    def __init__(self, default_rate: int = 60) -> None:
        """
        Initialize rate limiter.

        Args:
            default_rate: Default requests per minute
        """
        self._buckets: dict[str, TokenBucket] = {}
        self._default_rate = default_rate
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()

    def check_rate(self, client_id: str, rate_limit: int | None = None) -> bool:
        """
        Check if client is within rate limit.

        Args:
            client_id: Client identifier (IP or API key name)
            rate_limit: Optional custom rate limit

        Returns:
            True if request is allowed
        """
        self._maybe_cleanup()

        rate = rate_limit or self._default_rate

        if client_id not in self._buckets:
            self._buckets[client_id] = TokenBucket(capacity=rate)

        return self._buckets[client_id].consume()

    def get_remaining(self, client_id: str) -> int:
        """
        Get remaining requests for client.

        Args:
            client_id: Client identifier

        Returns:
            Number of remaining requests
        """
        if client_id not in self._buckets:
            return self._default_rate
        return int(self._buckets[client_id].tokens)

    def _maybe_cleanup(self) -> None:
        """Clean up old buckets periodically."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        # Remove buckets that haven't been used in 10 minutes
        cutoff = now - 600
        self._buckets = {
            k: v for k, v in self._buckets.items() if v.last_update > cutoff
        }
        self._last_cleanup = now


# Global rate limiter instance
rate_limiter = RateLimiter()


# ============================================================================
# Authentication Dependencies
# ============================================================================


async def get_api_key(
    header_key: str | None = Security(api_key_header),
    query_key: str | None = Security(api_key_query),
) -> APIKey:
    """
    FastAPI dependency to extract and validate API key.

    Args:
        header_key: API key from header
        query_key: API key from query parameter

    Returns:
        Valid APIKey object

    Raises:
        HTTPException: If no valid key provided
    """
    key = header_key or query_key

    if key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    api_key = key_manager.validate_key(key)

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


async def get_optional_api_key(
    header_key: str | None = Security(api_key_header),
    query_key: str | None = Security(api_key_query),
) -> APIKey | None:
    """
    FastAPI dependency for optional API key authentication.

    Returns None if no key provided instead of raising an error.
    """
    key = header_key or query_key

    if key is None:
        return None

    return key_manager.validate_key(key)


def require_permission(permission: str) -> Callable[[APIKey], APIKey]:
    """
    Create a dependency that requires a specific permission.

    Args:
        permission: Required permission name

    Returns:
        Dependency function
    """

    async def check_permission(api_key: APIKey = Security(get_api_key)) -> APIKey:
        if not api_key.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return api_key

    return check_permission


# ============================================================================
# Rate Limiting Middleware
# ============================================================================


async def check_rate_limit(request: Request, api_key: APIKey | None = None) -> None:
    """
    Check rate limit for request.

    Args:
        request: FastAPI request
        api_key: Optional API key for custom rate limit

    Raises:
        HTTPException: If rate limit exceeded
    """
    # Use API key name or client IP as identifier
    if api_key:
        client_id = api_key.name
        rate_limit = api_key.rate_limit
    else:
        client_id = request.client.host if request.client else "unknown"
        rate_limit = None

    if not rate_limiter.check_rate(client_id, rate_limit):
        remaining = rate_limiter.get_remaining(client_id)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "Retry-After": "60",
            },
        )


# ============================================================================
# mTLS Support
# ============================================================================


@dataclass
class ClientCertificate:
    """
    Parsed client certificate information.

    Attributes:
        subject: Certificate subject (CN)
        issuer: Certificate issuer
        serial: Certificate serial number
        not_before: Certificate validity start
        not_after: Certificate validity end
    """

    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime

    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = datetime.utcnow()
        return self.not_before <= now <= self.not_after


def extract_client_cert(request: Request) -> ClientCertificate | None:
    """
    Extract client certificate from request.

    This requires the server to be configured for mTLS and pass
    certificate information via headers (e.g., X-Client-Cert).

    Args:
        request: FastAPI request

    Returns:
        ClientCertificate if present and parseable
    """
    # Check for certificate in header (set by reverse proxy)
    cert_header = request.headers.get("X-Client-Cert")

    if not cert_header:
        return None

    # In production, parse the actual certificate
    # For now, return None to fall back to API key auth
    return None


async def get_mtls_or_api_key(
    request: Request,
    header_key: str | None = Security(api_key_header),
    query_key: str | None = Security(api_key_query),
) -> APIKey | ClientCertificate:
    """
    Authenticate via mTLS or API key.

    Tries mTLS first, falls back to API key.

    Args:
        request: FastAPI request
        header_key: API key from header
        query_key: API key from query

    Returns:
        APIKey or ClientCertificate

    Raises:
        HTTPException: If no valid authentication provided
    """
    # Try mTLS first
    cert = extract_client_cert(request)
    if cert and cert.is_valid():
        return cert

    # Fall back to API key
    key = header_key or query_key

    if key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (mTLS or API key)",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    api_key = key_manager.validate_key(key)

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


# ============================================================================
# Initialization
# ============================================================================


def init_auth(default_key: str | None = None) -> None:
    """
    Initialize authentication system.

    Args:
        default_key: Optional default API key for development
    """
    if default_key:
        key_manager.set_default_key(default_key)
        logger.info("Default API key configured")
    else:
        # Generate a random key for development if none provided
        key, _ = generate_api_key()
        key_manager.set_default_key(key)
        logger.warning(f"Generated development API key: {key}")
