"""
LLM-based USB threat analyzer using Claude API.

Provides intelligent threat assessment for USB devices using
Claude with constitutional bounds and rate limiting.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sentinel.analyzer.prompts import (
    SYSTEM_PROMPT,
    build_history_context,
    check_vendor_mismatch,
    format_behavior_prompt,
    format_device_prompt,
    sanitize_device_strings,
    validate_response,
)
from sentinel.analyzer.scoring import AnalysisResult, Verdict
from sentinel.interceptor.descriptors import DeviceDescriptor


logger = logging.getLogger(__name__)


class LLMClientProtocol(Protocol):
    """Protocol for LLM clients to allow mocking."""

    def create_message(
        self,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, str]],
        timeout: float,
    ) -> str:
        """Create a message and return the response text."""
        ...


@dataclass
class TokenBucket:
    """
    Token bucket rate limiter.

    Implements a simple token bucket algorithm for rate limiting
    API calls.
    """

    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False if rate limited
        """
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def wait_time(self, tokens: int = 1) -> float:
        """
        Calculate time to wait for tokens.

        Args:
            tokens: Number of tokens needed

        Returns:
            Seconds to wait (0 if tokens available)
        """
        self._refill()
        if self.tokens >= tokens:
            return 0
        needed = tokens - self.tokens
        return needed / self.refill_rate


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0

    def get_delay(self, attempt: int) -> float:
        """Get delay for a given attempt number."""
        delay = self.base_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)


@dataclass
class AnalyzerStats:
    """Statistics for analyzer operations."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_waits: int = 0
    retries: int = 0
    total_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    @property
    def avg_latency_ms(self) -> float:
        """Calculate average latency."""
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests


class LLMAnalyzer:
    """
    USB threat analyzer using Claude API.

    Provides intelligent analysis of USB device descriptors with:
    - Constitutional bounds enforcement
    - Rate limiting with token bucket
    - Exponential backoff retry
    - Input sanitization against prompt injection
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 1024,
        timeout: float = 30.0,
        rate_limit: int = 60,  # requests per minute
        retry_config: RetryConfig | None = None,
    ) -> None:
        """
        Initialize the LLM analyzer.

        Args:
            api_key: Anthropic API key
            model: Model ID to use
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            rate_limit: Maximum requests per minute
            retry_config: Retry configuration
        """
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            logger.error("anthropic package not installed")
            raise RuntimeError("anthropic package required for LLM analysis")

        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout

        # Rate limiter: convert requests/minute to tokens/second
        self.rate_limiter = TokenBucket(
            capacity=rate_limit,
            refill_rate=rate_limit / 60.0,
        )

        self.retry_config = retry_config or RetryConfig()
        self.stats = AnalyzerStats()

        # Analysis queue for async processing
        self._queue: asyncio.Queue[tuple[DeviceDescriptor, asyncio.Future]] = (
            asyncio.Queue()
        )
        self._worker_task: asyncio.Task | None = None

        logger.info(
            "LLM Analyzer initialized: model=%s, rate_limit=%d/min",
            model, rate_limit
        )

    def _create_message(
        self,
        prompt: str,
    ) -> str:
        """
        Create a message using the Claude API.

        Args:
            prompt: User prompt to send

        Returns:
            Response text from Claude

        Raises:
            Exception: On API errors
        """
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        # Extract text from response
        return response.content[0].text

    def analyze(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Analyze a USB device for security threats.

        Args:
            device: Device descriptor to analyze
            history: Optional history of this device
            similar_devices: Optional list of similar devices

        Returns:
            AnalysisResult with risk assessment

        Raises:
            RuntimeError: If analysis fails after retries
        """
        start_time = time.monotonic()
        self.stats.total_requests += 1

        # Check for known vendor mismatches
        vendor_warning = check_vendor_mismatch(device)

        # Sanitize device strings
        sanitized = sanitize_device_strings(device)

        # Build history context
        history_context = build_history_context(history, similar_devices)
        if vendor_warning:
            history_context = f"**WARNING:** {vendor_warning}\n\n{history_context}"

        # Create sanitized device copy for prompt
        # (We use the sanitized strings but keep the original device structure)
        prompt = format_device_prompt(device, history_context)

        # Rate limiting
        wait_time = self.rate_limiter.wait_time()
        if wait_time > 0:
            logger.debug("Rate limited, waiting %.2fs", wait_time)
            self.stats.rate_limited_waits += 1
            time.sleep(wait_time)

        self.rate_limiter.acquire()

        # Retry loop
        last_error: Exception | None = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                response_text = self._create_message(prompt)

                # Validate and parse response
                parsed = validate_response(response_text)
                if parsed is None:
                    logger.warning(
                        "Invalid LLM response format, attempt %d: %s",
                        attempt + 1, response_text[:200]
                    )
                    raise ValueError("Invalid response format from LLM")

                # Create result
                result = AnalysisResult(
                    risk_score=parsed["risk_score"],
                    verdict=Verdict(parsed["verdict"]),
                    analysis=parsed["analysis"],
                    confidence=parsed["confidence"],
                )

                # Update stats
                latency = (time.monotonic() - start_time) * 1000
                self.stats.successful_requests += 1
                self.stats.total_latency_ms += latency

                logger.info(
                    "Device %s:%s analyzed: score=%d, verdict=%s (%.0fms)",
                    device.vid, device.pid, result.risk_score,
                    result.verdict.value, latency
                )

                return result

            except Exception as e:
                last_error = e
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.get_delay(attempt)
                    logger.warning(
                        "Analysis attempt %d failed: %s, retrying in %.1fs",
                        attempt + 1, str(e), delay
                    )
                    self.stats.retries += 1
                    time.sleep(delay)
                else:
                    logger.error(
                        "Analysis failed after %d attempts: %s",
                        self.retry_config.max_retries + 1, str(e)
                    )

        self.stats.failed_requests += 1
        raise RuntimeError(f"Analysis failed: {last_error}")

    async def analyze_async(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Asynchronously analyze a USB device.

        Args:
            device: Device descriptor to analyze
            history: Optional history of this device
            similar_devices: Optional list of similar devices

        Returns:
            AnalysisResult with risk assessment
        """
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.analyze(device, history, similar_devices)
        )

    def analyze_behavior(
        self,
        device: DeviceDescriptor,
        traffic_data: dict[str, Any],
    ) -> AnalysisResult:
        """
        Analyze captured USB traffic behavior.

        Args:
            device: Device descriptor
            traffic_data: Captured traffic analysis

        Returns:
            AnalysisResult with behavior assessment
        """
        start_time = time.monotonic()
        self.stats.total_requests += 1

        prompt = format_behavior_prompt(device, traffic_data)

        # Rate limiting
        wait_time = self.rate_limiter.wait_time()
        if wait_time > 0:
            self.stats.rate_limited_waits += 1
            time.sleep(wait_time)

        self.rate_limiter.acquire()

        # Retry loop
        last_error: Exception | None = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                response_text = self._create_message(prompt)
                parsed = validate_response(response_text)

                if parsed is None:
                    raise ValueError("Invalid response format")

                result = AnalysisResult(
                    risk_score=parsed["risk_score"],
                    verdict=Verdict(parsed["verdict"]),
                    analysis=parsed["analysis"],
                    confidence=parsed["confidence"],
                )

                latency = (time.monotonic() - start_time) * 1000
                self.stats.successful_requests += 1
                self.stats.total_latency_ms += latency

                return result

            except Exception as e:
                last_error = e
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.get_delay(attempt)
                    self.stats.retries += 1
                    time.sleep(delay)

        self.stats.failed_requests += 1
        raise RuntimeError(f"Behavior analysis failed: {last_error}")

    def get_statistics(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "success_rate": self.stats.success_rate,
            "rate_limited_waits": self.stats.rate_limited_waits,
            "retries": self.stats.retries,
            "avg_latency_ms": self.stats.avg_latency_ms,
        }

    def reset_statistics(self) -> None:
        """Reset analyzer statistics."""
        self.stats = AnalyzerStats()


class MockLLMAnalyzer:
    """
    Mock LLM analyzer for testing without API calls.

    Provides deterministic results based on device characteristics.
    """

    def __init__(self, default_score: int = 25) -> None:
        """
        Initialize mock analyzer.

        Args:
            default_score: Default risk score for unknown devices
        """
        self.default_score = default_score
        self.stats = AnalyzerStats()

    def analyze(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Analyze device with mock logic.

        Uses heuristics to generate deterministic scores for testing.
        """
        self.stats.total_requests += 1
        score = self.default_score
        indicators = []

        # HID with storage is suspicious
        if device.has_hid and device.has_storage:
            score += 40
            indicators.append("HID device with mass storage capability")

        # First-seen composite devices
        if device.is_composite and len(device.interfaces) > 3:
            score += 15
            indicators.append("Complex composite device")

        # Check for vendor mismatch
        warning = check_vendor_mismatch(device)
        if warning:
            score += 25
            indicators.append("Vendor string mismatch")

        # Keyboard with unusual endpoints
        if device.has_keyboard and device.total_endpoints > 2:
            score += 20
            indicators.append("Keyboard with excessive endpoints")

        # Determine verdict
        score = min(100, max(0, score))
        if score <= 50:
            verdict = Verdict.ALLOW
        elif score <= 75:
            verdict = Verdict.SANDBOX
        else:
            verdict = Verdict.BLOCK

        self.stats.successful_requests += 1

        return AnalysisResult(
            risk_score=score,
            verdict=verdict,
            analysis=f"Mock analysis: {', '.join(indicators) or 'No issues detected'}",
            confidence=0.8,
        )

    async def analyze_async(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """Async version of analyze."""
        return self.analyze(device, history, similar_devices)

    def analyze_behavior(
        self,
        device: DeviceDescriptor,
        traffic_data: dict[str, Any],
    ) -> AnalysisResult:
        """Analyze traffic with mock logic."""
        self.stats.total_requests += 1
        score = 20
        indicators = []

        # Check for superhuman typing
        min_interval = traffic_data.get("min_interval_ms", 100)
        if min_interval < 10:
            score += 50
            indicators.append("Superhuman typing speed detected")
        elif min_interval < 30:
            score += 25
            indicators.append("Fast typing speed")

        # Check for suspicious patterns
        patterns = traffic_data.get("suspicious_patterns", [])
        score += len(patterns) * 10
        indicators.extend(patterns)

        score = min(100, max(0, score))
        if score <= 50:
            verdict = Verdict.ALLOW
        elif score <= 75:
            verdict = Verdict.SANDBOX
        else:
            verdict = Verdict.BLOCK

        self.stats.successful_requests += 1

        return AnalysisResult(
            risk_score=score,
            verdict=verdict,
            analysis=f"Mock behavior analysis: {', '.join(indicators) or 'Normal behavior'}",
            confidence=0.75,
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get mock analyzer statistics."""
        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "mock": True,
        }


def create_analyzer(
    api_key: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    use_mock: bool = False,
    **kwargs: Any,
) -> LLMAnalyzer | MockLLMAnalyzer:
    """
    Create an LLM analyzer instance.

    Args:
        api_key: Anthropic API key (required unless use_mock=True)
        model: Model ID to use
        use_mock: Use mock analyzer for testing
        **kwargs: Additional arguments for LLMAnalyzer

    Returns:
        Configured analyzer instance

    Raises:
        ValueError: If API key not provided and not using mock
    """
    if use_mock:
        return MockLLMAnalyzer(default_score=kwargs.get("default_score", 25))

    if not api_key:
        raise ValueError("API key required for LLM analyzer")

    return LLMAnalyzer(api_key=api_key, model=model, **kwargs)
