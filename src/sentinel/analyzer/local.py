"""
Local LLM fallback for offline USB threat analysis.

Provides offline analysis capability using llama.cpp when
the Claude API is unavailable.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.analyzer.prompts import (
    SYSTEM_PROMPT,
    build_history_context,
    check_vendor_mismatch,
    format_device_prompt,
    sanitize_device_strings,
    validate_response,
)
from sentinel.analyzer.scoring import AnalysisResult, Verdict
from sentinel.interceptor.descriptors import DeviceDescriptor


logger = logging.getLogger(__name__)


@dataclass
class LocalLLMConfig:
    """Configuration for local LLM."""

    model_path: str
    n_ctx: int = 4096
    n_gpu_layers: int = 0
    n_threads: int = 4
    temperature: float = 0.1
    max_tokens: int = 512


class LocalLLMAnalyzer:
    """
    Local LLM analyzer using llama-cpp-python.

    Provides offline analysis capability when Claude API is unavailable.
    Uses smaller models optimized for the USB analysis task.
    """

    def __init__(self, config: LocalLLMConfig) -> None:
        """
        Initialize the local LLM analyzer.

        Args:
            config: Local LLM configuration

        Raises:
            RuntimeError: If llama-cpp-python is not installed
            FileNotFoundError: If model file not found
        """
        self.config = config

        # Check model file exists
        model_path = Path(config.model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {config.model_path}")

        try:
            from llama_cpp import Llama
            self._llm_class = Llama
        except ImportError:
            raise RuntimeError(
                "llama-cpp-python not installed. Install with: "
                "pip install llama-cpp-python"
            )

        # Lazy initialization of model
        self._model: Any = None
        self._initialized = False

        # Statistics
        self._total_requests = 0
        self._successful_requests = 0
        self._failed_requests = 0
        self._total_latency_ms = 0.0

        logger.info(
            "Local LLM Analyzer configured: model=%s, n_ctx=%d, gpu_layers=%d",
            config.model_path, config.n_ctx, config.n_gpu_layers
        )

    def _ensure_initialized(self) -> None:
        """Initialize the model lazily on first use."""
        if self._initialized:
            return

        logger.info("Loading local LLM model: %s", self.config.model_path)
        start_time = time.monotonic()

        self._model = self._llm_class(
            model_path=self.config.model_path,
            n_ctx=self.config.n_ctx,
            n_gpu_layers=self.config.n_gpu_layers,
            n_threads=self.config.n_threads,
            verbose=False,
        )

        load_time = (time.monotonic() - start_time) * 1000
        logger.info("Local LLM model loaded in %.0fms", load_time)
        self._initialized = True

    def _create_prompt(self, user_prompt: str) -> str:
        """
        Create a complete prompt for the local model.

        Formats the prompt in a way suitable for instruction-tuned models.
        """
        # Format for Llama-2-chat style models
        return f"""<s>[INST] <<SYS>>
{SYSTEM_PROMPT}
<</SYS>>

{user_prompt} [/INST]"""

    def analyze(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Analyze a USB device using local LLM.

        Args:
            device: Device descriptor to analyze
            history: Optional history of this device
            similar_devices: Optional list of similar devices

        Returns:
            AnalysisResult with risk assessment

        Raises:
            RuntimeError: If analysis fails
        """
        self._ensure_initialized()
        start_time = time.monotonic()
        self._total_requests += 1

        # Check for vendor mismatches
        vendor_warning = check_vendor_mismatch(device)

        # Build history context
        history_context = build_history_context(history, similar_devices)
        if vendor_warning:
            history_context = f"**WARNING:** {vendor_warning}\n\n{history_context}"

        # Create prompt
        user_prompt = format_device_prompt(device, history_context)
        full_prompt = self._create_prompt(user_prompt)

        try:
            # Generate response
            response = self._model(
                full_prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                stop=["</s>", "[INST]"],
            )

            response_text = response["choices"][0]["text"]

            # Validate response
            parsed = validate_response(response_text)
            if parsed is None:
                logger.warning("Invalid local LLM response: %s", response_text[:200])
                # Fall back to heuristic analysis
                return self._heuristic_fallback(device, "Invalid LLM response format")

            result = AnalysisResult(
                risk_score=parsed["risk_score"],
                verdict=Verdict(parsed["verdict"]),
                analysis=parsed["analysis"],
                confidence=parsed["confidence"] * 0.8,  # Lower confidence for local
            )

            latency = (time.monotonic() - start_time) * 1000
            self._successful_requests += 1
            self._total_latency_ms += latency

            logger.info(
                "Local analysis for %s:%s: score=%d, verdict=%s (%.0fms)",
                device.vid, device.pid, result.risk_score,
                result.verdict.value, latency
            )

            return result

        except Exception as e:
            logger.error("Local LLM analysis failed: %s", str(e))
            self._failed_requests += 1
            return self._heuristic_fallback(device, str(e))

    def _heuristic_fallback(
        self,
        device: DeviceDescriptor,
        error_reason: str,
    ) -> AnalysisResult:
        """
        Fall back to heuristic analysis when LLM fails.

        Args:
            device: Device descriptor
            error_reason: Why LLM analysis failed

        Returns:
            Heuristic-based AnalysisResult
        """
        score = 40  # Start with cautious baseline
        indicators = []

        # HID with storage is very suspicious
        if device.has_hid and device.has_storage:
            score += 35
            indicators.append("HID device with mass storage interface")

        # Keyboard with too many endpoints
        if device.has_keyboard and device.total_endpoints > 2:
            score += 20
            indicators.append("Keyboard with unusual endpoint count")

        # Vendor mismatch
        warning = check_vendor_mismatch(device)
        if warning:
            score += 25
            indicators.append("Vendor string mismatch detected")

        # Complex composite device
        if len(device.interfaces) > 4:
            score += 15
            indicators.append("Complex composite device")

        # No manufacturer or product string on HID
        if device.has_hid and not device.manufacturer and not device.product:
            score += 15
            indicators.append("HID device without vendor identification")

        score = min(100, max(0, score))

        if score <= 50:
            verdict = Verdict.SANDBOX  # Be cautious on fallback
        elif score <= 75:
            verdict = Verdict.SANDBOX
        else:
            verdict = Verdict.BLOCK

        analysis = (
            f"Heuristic analysis (LLM unavailable: {error_reason}). "
            f"Indicators: {', '.join(indicators) if indicators else 'None'}. "
            "Recommend manual review."
        )

        return AnalysisResult(
            risk_score=score,
            verdict=verdict,
            analysis=analysis[:500],
            confidence=0.5,  # Low confidence for heuristic
        )

    async def analyze_async(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Async wrapper for analyze.

        Note: Local LLM is CPU-bound, so this runs in executor.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.analyze(device, history, similar_devices)
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        avg_latency = (
            self._total_latency_ms / self._successful_requests
            if self._successful_requests > 0
            else 0.0
        )
        return {
            "total_requests": self._total_requests,
            "successful_requests": self._successful_requests,
            "failed_requests": self._failed_requests,
            "avg_latency_ms": avg_latency,
            "model_path": self.config.model_path,
            "initialized": self._initialized,
            "type": "local",
        }

    def unload(self) -> None:
        """Unload the model to free memory."""
        if self._model is not None:
            del self._model
            self._model = None
            self._initialized = False
            logger.info("Local LLM model unloaded")


class HybridAnalyzer:
    """
    Hybrid analyzer that uses Claude API with local LLM fallback.

    Automatically falls back to local LLM when:
    - Claude API is unavailable
    - Rate limit is exceeded
    - Network errors occur
    """

    def __init__(
        self,
        primary_analyzer: Any,  # LLMAnalyzer
        fallback_analyzer: LocalLLMAnalyzer,
        fallback_on_error: bool = True,
    ) -> None:
        """
        Initialize hybrid analyzer.

        Args:
            primary_analyzer: Primary LLM analyzer (Claude API)
            fallback_analyzer: Fallback local LLM analyzer
            fallback_on_error: Whether to fall back on errors
        """
        self.primary = primary_analyzer
        self.fallback = fallback_analyzer
        self.fallback_on_error = fallback_on_error

        self._primary_failures = 0
        self._fallback_uses = 0

    def analyze(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """
        Analyze with automatic fallback.

        Args:
            device: Device descriptor to analyze
            history: Optional device history
            similar_devices: Optional similar devices

        Returns:
            AnalysisResult from primary or fallback analyzer
        """
        try:
            return self.primary.analyze(device, history, similar_devices)
        except Exception as e:
            self._primary_failures += 1
            logger.warning(
                "Primary analyzer failed (%s), using fallback",
                str(e)
            )

            if self.fallback_on_error:
                self._fallback_uses += 1
                return self.fallback.analyze(device, history, similar_devices)
            raise

    async def analyze_async(
        self,
        device: DeviceDescriptor,
        history: list[dict[str, Any]] | None = None,
        similar_devices: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        """Async analysis with fallback."""
        try:
            return await self.primary.analyze_async(device, history, similar_devices)
        except Exception as e:
            self._primary_failures += 1
            logger.warning("Primary analyzer failed, using fallback: %s", str(e))

            if self.fallback_on_error:
                self._fallback_uses += 1
                return await self.fallback.analyze_async(
                    device, history, similar_devices
                )
            raise

    def get_statistics(self) -> dict[str, Any]:
        """Get combined statistics."""
        return {
            "primary": self.primary.get_statistics(),
            "fallback": self.fallback.get_statistics(),
            "primary_failures": self._primary_failures,
            "fallback_uses": self._fallback_uses,
        }


def create_local_analyzer(
    model_path: str,
    n_ctx: int = 4096,
    n_gpu_layers: int = 0,
    n_threads: int = 4,
) -> LocalLLMAnalyzer:
    """
    Create a local LLM analyzer.

    Args:
        model_path: Path to GGUF model file
        n_ctx: Context window size
        n_gpu_layers: Number of layers to offload to GPU
        n_threads: Number of CPU threads

    Returns:
        Configured LocalLLMAnalyzer

    Raises:
        RuntimeError: If llama-cpp-python not installed
        FileNotFoundError: If model not found
    """
    config = LocalLLMConfig(
        model_path=model_path,
        n_ctx=n_ctx,
        n_gpu_layers=n_gpu_layers,
        n_threads=n_threads,
    )
    return LocalLLMAnalyzer(config)
