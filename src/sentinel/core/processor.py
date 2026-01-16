"""
Device Processor - Integrated Evaluation Pipeline.

Ties together the interceptor, policy engine, validator, and audit database
to provide complete device evaluation and decision making.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

from sentinel.audit.database import AuditDatabase
from sentinel.audit.models import EventType as AuditEventType, TrustLevel
from sentinel.interceptor.descriptors import DeviceDescriptor
from sentinel.interceptor.validator import ValidationResult, validate_descriptor
from sentinel.policy.engine import EvaluationResult, PolicyEngine
from sentinel.policy.fingerprint import FingerprintDatabase, generate_fingerprint
from sentinel.policy.models import Action


logger = logging.getLogger(__name__)


class Verdict(Enum):
    """Final verdict for a device."""

    ALLOW = "allow"
    BLOCK = "block"
    SANDBOX = "sandbox"
    REVIEW = "review"  # Needs LLM analysis


@dataclass
class ProcessingResult:
    """
    Complete result of device processing.

    Combines policy evaluation, validation, and final verdict.
    """

    # Device info
    device: DeviceDescriptor
    fingerprint: str

    # Policy evaluation
    policy_result: EvaluationResult

    # Validation
    validation_result: ValidationResult

    # Final decision
    verdict: Verdict
    risk_score: int  # 0-100 combined score

    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    processing_time_ms: float = 0.0
    llm_analysis: str | None = None

    # Flags
    is_first_seen: bool = False
    requires_llm: bool = False

    @property
    def should_allow(self) -> bool:
        """Check if device should be allowed."""
        return self.verdict == Verdict.ALLOW

    @property
    def should_block(self) -> bool:
        """Check if device should be blocked."""
        return self.verdict == Verdict.BLOCK

    @property
    def needs_sandbox(self) -> bool:
        """Check if device needs sandboxing."""
        return self.verdict == Verdict.SANDBOX

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/API."""
        return {
            "fingerprint": self.fingerprint,
            "vid": self.device.vid,
            "pid": self.device.pid,
            "product": self.device.product,
            "manufacturer": self.device.manufacturer,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "policy_action": self.policy_result.action.value,
            "policy_rule": self.policy_result.rule_index,
            "validation_score": self.validation_result.risk_score,
            "anomaly_count": len(self.validation_result.anomalies),
            "is_first_seen": self.is_first_seen,
            "requires_llm": self.requires_llm,
            "timestamp": self.timestamp.isoformat(),
            "processing_time_ms": self.processing_time_ms,
        }


# Type for async hooks
AsyncHook = Callable[[DeviceDescriptor, ProcessingResult], Coroutine[Any, Any, None]]
SyncHook = Callable[[DeviceDescriptor, ProcessingResult], None]


class DeviceProcessor:
    """
    Integrated device processing pipeline.

    Coordinates policy evaluation, validation, and audit logging
    to produce a final verdict for each device.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_db: AuditDatabase | None = None,
        fingerprint_db: FingerprintDatabase | None = None,
        review_threshold: int = 50,
        block_threshold: int = 75,
        sandbox_threshold: int = 60,
    ) -> None:
        """
        Initialize the device processor.

        Args:
            policy_engine: Policy engine for rule evaluation
            audit_db: Audit database for logging (optional)
            fingerprint_db: Fingerprint database for tracking
            review_threshold: Risk score threshold for LLM review
            block_threshold: Risk score threshold for blocking
            sandbox_threshold: Risk score threshold for sandboxing
        """
        self.policy_engine = policy_engine
        self.audit_db = audit_db
        self.fingerprint_db = fingerprint_db or FingerprintDatabase()

        self.review_threshold = review_threshold
        self.block_threshold = block_threshold
        self.sandbox_threshold = sandbox_threshold

        # Hooks for extensibility
        self._pre_process_hooks: list[SyncHook] = []
        self._post_process_hooks: list[SyncHook] = []
        self._async_post_hooks: list[AsyncHook] = []

        # Statistics
        self._processed = 0
        self._allowed = 0
        self._blocked = 0
        self._sandboxed = 0
        self._reviewed = 0

    def process(self, device: DeviceDescriptor) -> ProcessingResult:
        """
        Process a device through the complete pipeline.

        Args:
            device: Device descriptor to process

        Returns:
            ProcessingResult with final verdict
        """
        start_time = datetime.utcnow()

        # Generate fingerprint
        fingerprint = generate_fingerprint(device)
        is_first_seen = self.fingerprint_db.is_first_seen(fingerprint)

        # Run pre-process hooks
        for hook in self._pre_process_hooks:
            try:
                hook(device, None)  # type: ignore
            except Exception as e:
                logger.error("Pre-process hook error: %s", e)

        # Step 1: Policy evaluation
        policy_result = self.policy_engine.evaluate(device)

        # Step 2: Descriptor validation
        validation_result = validate_descriptor(device)

        # Step 3: Compute combined risk score
        risk_score = self._compute_risk_score(
            policy_result, validation_result, is_first_seen
        )

        # Step 4: Determine final verdict
        verdict, requires_llm = self._determine_verdict(
            policy_result, validation_result, risk_score
        )

        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Create result
        result = ProcessingResult(
            device=device,
            fingerprint=fingerprint,
            policy_result=policy_result,
            validation_result=validation_result,
            verdict=verdict,
            risk_score=risk_score,
            processing_time_ms=processing_time,
            is_first_seen=is_first_seen,
            requires_llm=requires_llm,
        )

        # Update fingerprint database
        if is_first_seen:
            fp = self.policy_engine.fingerprint_db
            if hasattr(fp, 'add'):
                from sentinel.policy.fingerprint import DeviceFingerprint
                fp_obj = DeviceFingerprint(
                    fingerprint=fingerprint,
                    full_hash=fingerprint,
                    vid=device.vid,
                    pid=device.pid,
                    components=[],
                    created_at=datetime.utcnow(),
                )
                fp.add(fp_obj)

        # Log to audit database
        if self.audit_db:
            self._log_to_audit(device, result)

        # Update statistics
        self._update_stats(verdict)

        # Run post-process hooks
        for hook in self._post_process_hooks:
            try:
                hook(device, result)
            except Exception as e:
                logger.error("Post-process hook error: %s", e)

        logger.info(
            "Processed device %s:%s -> %s (score=%d, time=%.1fms)",
            device.vid, device.pid, verdict.value, risk_score, processing_time
        )

        return result

    async def process_async(self, device: DeviceDescriptor) -> ProcessingResult:
        """
        Process a device asynchronously.

        Allows for async post-processing hooks (e.g., LLM analysis).

        Args:
            device: Device descriptor to process

        Returns:
            ProcessingResult with final verdict
        """
        # Run sync processing
        result = self.process(device)

        # Run async post-process hooks
        for hook in self._async_post_hooks:
            try:
                await hook(device, result)
            except Exception as e:
                logger.error("Async post-process hook error: %s", e)

        return result

    def _compute_risk_score(
        self,
        policy_result: EvaluationResult,
        validation_result: ValidationResult,
        is_first_seen: bool,
    ) -> int:
        """
        Compute combined risk score from all factors.

        Args:
            policy_result: Policy evaluation result
            validation_result: Validation result
            is_first_seen: Whether device is newly seen

        Returns:
            Risk score 0-100
        """
        score = 0

        # Base score from policy action
        if policy_result.action == Action.BLOCK:
            score += 50
        elif policy_result.action == Action.REVIEW:
            score += 25

        # Add validation score (capped at 50)
        score += min(50, validation_result.risk_score)

        # First-seen penalty
        if is_first_seen:
            score += 10

        return min(100, score)

    def _determine_verdict(
        self,
        policy_result: EvaluationResult,
        validation_result: ValidationResult,
        risk_score: int,
    ) -> tuple[Verdict, bool]:
        """
        Determine final verdict based on all factors.

        Args:
            policy_result: Policy evaluation result
            validation_result: Validation result
            risk_score: Combined risk score

        Returns:
            Tuple of (Verdict, requires_llm)
        """
        requires_llm = False

        # Explicit BLOCK from policy always blocks
        if policy_result.action == Action.BLOCK:
            return Verdict.BLOCK, False

        # Explicit ALLOW from policy
        if policy_result.action == Action.ALLOW:
            # But check if validation found critical issues
            if validation_result.risk_score >= self.block_threshold:
                logger.warning(
                    "Policy allows but validation score %d exceeds block threshold",
                    validation_result.risk_score
                )
                return Verdict.SANDBOX, True
            return Verdict.ALLOW, False

        # REVIEW action - need to decide based on scores
        if risk_score >= self.block_threshold:
            return Verdict.BLOCK, True

        if risk_score >= self.sandbox_threshold:
            return Verdict.SANDBOX, True

        if risk_score >= self.review_threshold:
            requires_llm = True
            return Verdict.REVIEW, True

        # Low risk - allow with monitoring
        return Verdict.ALLOW, False

    def _log_to_audit(
        self,
        device: DeviceDescriptor,
        result: ProcessingResult,
    ) -> None:
        """Log processing result to audit database."""
        if not self.audit_db:
            return

        try:
            # Ensure device exists
            self.audit_db.add_device(
                fingerprint=result.fingerprint,
                vid=device.vid,
                pid=device.pid,
                manufacturer=device.manufacturer,
                product=device.product,
                serial=device.serial,
            )

            # Map verdict to event type
            event_type_map = {
                Verdict.ALLOW: AuditEventType.ALLOWED,
                Verdict.BLOCK: AuditEventType.BLOCKED,
                Verdict.SANDBOX: AuditEventType.SANDBOXED,
                Verdict.REVIEW: AuditEventType.REVIEWED,
            }

            # Log event
            self.audit_db.log_event(
                device_fingerprint=result.fingerprint,
                event_type=event_type_map[result.verdict],
                policy_rule=result.policy_result.reason,
                risk_score=result.risk_score,
                verdict=result.verdict.value,
                raw_descriptor=device.to_dict(),
            )

        except Exception as e:
            logger.error("Failed to log to audit database: %s", e)

    def _update_stats(self, verdict: Verdict) -> None:
        """Update processing statistics."""
        self._processed += 1
        if verdict == Verdict.ALLOW:
            self._allowed += 1
        elif verdict == Verdict.BLOCK:
            self._blocked += 1
        elif verdict == Verdict.SANDBOX:
            self._sandboxed += 1
        else:
            self._reviewed += 1

    def add_pre_process_hook(self, hook: SyncHook) -> None:
        """Add a pre-processing hook."""
        self._pre_process_hooks.append(hook)

    def add_post_process_hook(self, hook: SyncHook) -> None:
        """Add a post-processing hook."""
        self._post_process_hooks.append(hook)

    def add_async_post_hook(self, hook: AsyncHook) -> None:
        """Add an async post-processing hook."""
        self._async_post_hooks.append(hook)

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics."""
        return {
            "total_processed": self._processed,
            "allowed": self._allowed,
            "blocked": self._blocked,
            "sandboxed": self._sandboxed,
            "reviewed": self._reviewed,
            "policy_stats": self.policy_engine.get_statistics(),
        }

    def reset_statistics(self) -> None:
        """Reset processing statistics."""
        self._processed = 0
        self._allowed = 0
        self._blocked = 0
        self._sandboxed = 0
        self._reviewed = 0
        self.policy_engine.reset_statistics()

    def update_verdict_with_llm(
        self,
        result: ProcessingResult,
        llm_score: int,
        llm_analysis: str,
    ) -> ProcessingResult:
        """
        Update verdict after LLM analysis.

        Args:
            result: Original processing result
            llm_score: Risk score from LLM (0-100)
            llm_analysis: Analysis text from LLM

        Returns:
            Updated ProcessingResult
        """
        # Combine scores
        combined_score = (result.risk_score + llm_score) // 2
        result.risk_score = combined_score
        result.llm_analysis = llm_analysis

        # Re-evaluate verdict
        if llm_score >= self.block_threshold:
            result.verdict = Verdict.BLOCK
        elif llm_score >= self.sandbox_threshold:
            result.verdict = Verdict.SANDBOX
        elif llm_score <= 25:
            result.verdict = Verdict.ALLOW
        else:
            result.verdict = Verdict.SANDBOX  # Cautious default

        result.requires_llm = False

        # Update audit log
        if self.audit_db:
            try:
                event_type_map = {
                    Verdict.ALLOW: AuditEventType.ALLOWED,
                    Verdict.BLOCK: AuditEventType.BLOCKED,
                    Verdict.SANDBOX: AuditEventType.SANDBOXED,
                    Verdict.REVIEW: AuditEventType.REVIEWED,
                }
                self.audit_db.log_event(
                    device_fingerprint=result.fingerprint,
                    event_type=event_type_map[result.verdict],
                    llm_analysis=llm_analysis,
                    risk_score=combined_score,
                    verdict=result.verdict.value,
                )
            except Exception as e:
                logger.error("Failed to log LLM result: %s", e)

        return result


class PolicyWatcher:
    """
    Watches policy file for changes and hot-reloads.
    """

    def __init__(
        self,
        policy_path: str | Path,
        processor: DeviceProcessor,
        check_interval: float = 5.0,
    ) -> None:
        """
        Initialize the policy watcher.

        Args:
            policy_path: Path to policy file to watch
            processor: Device processor to update
            check_interval: Interval in seconds between checks
        """
        self.policy_path = Path(policy_path)
        self.processor = processor
        self.check_interval = check_interval
        self._last_mtime: float | None = None
        self._running = False

    async def watch(self) -> None:
        """
        Start watching for policy changes.

        Runs until stopped.
        """
        self._running = True
        self._last_mtime = self._get_mtime()

        logger.info("Policy watcher started: %s", self.policy_path)

        while self._running:
            try:
                await asyncio.sleep(self.check_interval)

                current_mtime = self._get_mtime()
                if current_mtime != self._last_mtime:
                    logger.info("Policy file changed, reloading...")
                    self._reload_policy()
                    self._last_mtime = current_mtime

            except Exception as e:
                logger.error("Policy watcher error: %s", e)

    def stop(self) -> None:
        """Stop watching."""
        self._running = False

    def _get_mtime(self) -> float | None:
        """Get file modification time."""
        try:
            return self.policy_path.stat().st_mtime
        except OSError:
            return None

    def _reload_policy(self) -> None:
        """Reload policy from file."""
        try:
            errors = self.processor.policy_engine.reload_policy(self.policy_path)
            for error in errors:
                logger.warning("Policy reload warning: %s", error)
            logger.info(
                "Policy reloaded: %d rules",
                len(self.processor.policy_engine.policy.rules)
            )
        except Exception as e:
            logger.error("Failed to reload policy: %s", e)


def create_processor(
    policy_path: str | Path | None = None,
    db_path: str | Path | None = None,
) -> DeviceProcessor:
    """
    Create a fully configured device processor.

    Args:
        policy_path: Path to policy YAML file (uses default if None)
        db_path: Path to audit database (uses memory if None)

    Returns:
        Configured DeviceProcessor
    """
    from sentinel.policy.engine import create_default_policy

    # Create policy engine
    if policy_path:
        policy_engine = PolicyEngine.from_file(policy_path)
    else:
        policy_engine = PolicyEngine(policy=create_default_policy())

    # Create audit database
    audit_db = None
    if db_path:
        audit_db = AuditDatabase(db_path)

    return DeviceProcessor(
        policy_engine=policy_engine,
        audit_db=audit_db,
    )
