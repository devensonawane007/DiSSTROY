"""Thread-safe and async Shared State engine for DiSSTROY."""

import asyncio
import json
from typing import Any, Callable, Coroutine, Dict, List, Optional
from datetime import datetime, timezone
import aiosqlite

from disstroy.models.asset import Asset
from disstroy.models.observation import Observation
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.failure import FailureRecord, FailureLesson
from disstroy.models.path import AttackPath
from disstroy.models.enums import (
    AccessLevel,
    FailureCategory,
    HypothesisCategory,
    HypothesisStatus,
    PathRisk,
    PathStatus,
)
from disstroy.state.db import DatabaseManager


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateChangeEvent:
    """Event emitted whenever the shared state mutates."""

    def __init__(self, event_type: str, entity_id: str, payload: Dict[str, Any]):
        self.event_type = event_type
        self.entity_id = entity_id
        self.payload = payload
        self.timestamp = _now_iso()

    def __repr__(self) -> str:
        return f"<StateChangeEvent {self.event_type} entity={self.entity_id}>"


class SharedState:
    """Persistent shared knowledge engine backed by SQLite and reactive event bus."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self._listeners: List[Callable[[StateChangeEvent], Coroutine[Any, Any, None]]] = []
        self._lock = asyncio.Lock()

    def subscribe(self, callback: Callable[[StateChangeEvent], Coroutine[Any, Any, None]]) -> None:
        """Register a subscriber callback for state changes."""
        self._listeners.append(callback)

    async def _emit(self, event_type: str, entity_id: str, payload: Dict[str, Any]) -> None:
        """Record event in history and notify subscribers."""
        event = StateChangeEvent(event_type, entity_id, payload)
        # Record into history table
        async with self._lock:
            await self.db.conn.execute(
                "INSERT INTO history (event_type, entity_id, payload, timestamp) VALUES (?, ?, ?, ?)",
                (event.event_type, event.entity_id, json.dumps(event.payload), event.timestamp),
            )
            await self.db.conn.commit()

        # Notify listeners
        for listener in self._listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    await listener(event)
                else:
                    listener(event)
            except Exception as e:
                # Log listener failure without breaking state mutations
                pass

    # ---------------- Asset Operations ----------------

    async def add_asset(self, asset: Asset) -> None:
        """Insert or replace an asset."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO assets (
                    id, name, asset_type, criticality, network_location,
                    current_access_level, is_canary_objective, canary_description,
                    tags, metadata, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    criticality=excluded.criticality,
                    network_location=excluded.network_location,
                    current_access_level=excluded.current_access_level,
                    is_canary_objective=excluded.is_canary_objective,
                    canary_description=excluded.canary_description,
                    tags=excluded.tags,
                    metadata=excluded.metadata,
                    updated_at=excluded.updated_at
                """,
                (
                    asset.id,
                    asset.name,
                    asset.asset_type.value,
                    asset.criticality,
                    asset.network_location,
                    asset.current_access_level.value if hasattr(asset.current_access_level, "value") else str(asset.current_access_level),
                    1 if asset.is_canary_objective else 0,
                    asset.canary_description,
                    json.dumps(asset.tags),
                    json.dumps(asset.metadata),
                    asset.created_at,
                    asset.updated_at,
                ),
            )
            await self.db.conn.commit()

        await self._emit("ASSET_ADDED", asset.id, asset.model_dump())

    async def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Retrieve an asset by ID."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            keys = row.keys()
            return Asset(
                id=row["id"],
                name=row["name"],
                asset_type=row["asset_type"],
                criticality=row["criticality"],
                network_location=row["network_location"] or "",
                current_access_level=AccessLevel(row["current_access_level"]) if ("current_access_level" in keys and row["current_access_level"]) else AccessLevel.NONE,
                is_canary_objective=bool(row["is_canary_objective"]) if "is_canary_objective" in keys else False,
                canary_description=row["canary_description"] if "canary_description" in keys else None,
                tags=json.loads(row["tags"] or "[]"),
                metadata=json.loads(row["metadata"] or "{}"),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    async def list_assets(self) -> List[Asset]:
        """List all registered assets."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM assets ORDER BY criticality DESC")
            rows = await cursor.fetchall()
            assets = []
            for r in rows:
                keys = r.keys()
                assets.append(
                    Asset(
                        id=r["id"],
                        name=r["name"],
                        asset_type=r["asset_type"],
                        criticality=r["criticality"],
                        network_location=r["network_location"] or "",
                        current_access_level=AccessLevel(r["current_access_level"]) if ("current_access_level" in keys and r["current_access_level"]) else AccessLevel.NONE,
                        is_canary_objective=bool(r["is_canary_objective"]) if "is_canary_objective" in keys else False,
                        canary_description=r["canary_description"] if "canary_description" in keys else None,
                        tags=json.loads(r["tags"] or "[]"),
                        metadata=json.loads(r["metadata"] or "{}"),
                        created_at=r["created_at"],
                        updated_at=r["updated_at"],
                    )
                )
            return assets

    # ---------------- Observation Operations ----------------

    async def add_observation(self, obs: Observation) -> None:
        """Insert a new observation into state."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO observations (id, asset_id, kind, title, raw_payload, confidence, source, tags, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    obs.id,
                    obs.asset_id,
                    obs.kind.value,
                    obs.title,
                    json.dumps(obs.raw_payload),
                    obs.confidence,
                    obs.source,
                    json.dumps(obs.tags),
                    obs.timestamp,
                ),
            )
            await self.db.conn.commit()

        await self._emit("OBSERVATION_ADDED", obs.id, obs.model_dump())

    async def get_observation(self, obs_id: str) -> Optional[Observation]:
        """Retrieve an observation by ID."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM observations WHERE id = ?", (obs_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            return Observation(
                id=row["id"],
                asset_id=row["asset_id"],
                kind=row["kind"],
                title=row["title"],
                raw_payload=json.loads(row["raw_payload"] or "{}"),
                confidence=row["confidence"],
                source=row["source"],
                tags=json.loads(row["tags"] or "[]"),
                timestamp=row["timestamp"],
            )

    async def list_observations(self, asset_id: Optional[str] = None) -> List[Observation]:
        """List all observations or observations for an asset."""
        async with self._lock:
            if asset_id:
                cursor = await self.db.conn.execute(
                    "SELECT * FROM observations WHERE asset_id = ? ORDER BY timestamp ASC", (asset_id,)
                )
            else:
                cursor = await self.db.conn.execute("SELECT * FROM observations ORDER BY timestamp ASC")
            rows = await cursor.fetchall()
            return [
                Observation(
                    id=r["id"],
                    asset_id=r["asset_id"],
                    kind=r["kind"],
                    title=r["title"],
                    raw_payload=json.loads(r["raw_payload"] or "{}"),
                    confidence=r["confidence"],
                    source=r["source"],
                    tags=json.loads(r["tags"] or "[]"),
                    timestamp=r["timestamp"],
                )
                for r in rows
            ]

    # ---------------- Hypothesis Operations ----------------

    async def add_hypothesis(self, hyp: Hypothesis) -> None:
        """Insert a newly formulated hypothesis."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO hypotheses (
                    id, target_asset_id, category, title, description, supporting_obs, refuting_obs,
                    prerequisite_hypotheses, required_access_level, enables_access_level, stage,
                    prior_prob, confidence, priority_score, status, test_plan, assigned_worker_id,
                    generated_by_provider, generated_by_model, is_fallback, fallback_reason,
                    metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    supporting_obs=excluded.supporting_obs,
                    refuting_obs=excluded.refuting_obs,
                    prerequisite_hypotheses=excluded.prerequisite_hypotheses,
                    required_access_level=excluded.required_access_level,
                    enables_access_level=excluded.enables_access_level,
                    stage=excluded.stage,
                    confidence=excluded.confidence,
                    priority_score=excluded.priority_score,
                    status=CASE
                        WHEN hypotheses.status IN ('VALIDATED', 'REFUTED', 'ABANDONED') THEN hypotheses.status
                        ELSE excluded.status
                    END,
                    assigned_worker_id=excluded.assigned_worker_id,
                    generated_by_provider=excluded.generated_by_provider,
                    generated_by_model=excluded.generated_by_model,
                    is_fallback=excluded.is_fallback,
                    fallback_reason=excluded.fallback_reason,
                    updated_at=excluded.updated_at
                """,
                (
                    hyp.id,
                    hyp.target_asset_id,
                    hyp.category.value,
                    hyp.title,
                    hyp.description,
                    json.dumps(hyp.supporting_observation_ids),
                    json.dumps(hyp.refuting_observation_ids),
                    json.dumps(hyp.prerequisite_hypothesis_ids),
                    hyp.required_access_level.value if hasattr(hyp.required_access_level, "value") else str(hyp.required_access_level),
                    hyp.enables_access_level.value if hyp.enables_access_level and hasattr(hyp.enables_access_level, "value") else (str(hyp.enables_access_level) if hyp.enables_access_level else None),
                    hyp.stage,
                    hyp.prior_probability,
                    hyp.confidence,
                    hyp.priority_score,
                    hyp.status.value,
                    json.dumps([p.model_dump() for p in hyp.test_plan]),
                    hyp.assigned_worker_id,
                    hyp.generated_by_provider,
                    hyp.generated_by_model,
                    1 if hyp.is_fallback else 0,
                    hyp.fallback_reason,
                    json.dumps(hyp.metadata),
                    hyp.created_at,
                    hyp.updated_at,
                ),
            )
            await self.db.conn.commit()

        await self._emit("HYPOTHESIS_ADDED", hyp.id, hyp.model_dump())

    async def update_hypothesis(self, hyp: Hypothesis) -> None:
        """Update an existing hypothesis."""
        hyp.updated_at = _now_iso()
        async with self._lock:
            await self.db.conn.execute(
                """
                UPDATE hypotheses SET
                    supporting_obs = ?,
                    refuting_obs = ?,
                    prerequisite_hypotheses = ?,
                    required_access_level = ?,
                    enables_access_level = ?,
                    stage = ?,
                    confidence = ?,
                    priority_score = ?,
                    status = ?,
                    test_plan = ?,
                    assigned_worker_id = ?,
                    generated_by_provider = ?,
                    generated_by_model = ?,
                    is_fallback = ?,
                    fallback_reason = ?,
                    metadata = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(hyp.supporting_observation_ids),
                    json.dumps(hyp.refuting_observation_ids),
                    json.dumps(hyp.prerequisite_hypothesis_ids),
                    hyp.required_access_level.value if hasattr(hyp.required_access_level, "value") else str(hyp.required_access_level),
                    hyp.enables_access_level.value if hyp.enables_access_level and hasattr(hyp.enables_access_level, "value") else (str(hyp.enables_access_level) if hyp.enables_access_level else None),
                    hyp.stage,
                    hyp.confidence,
                    hyp.priority_score,
                    hyp.status.value,
                    json.dumps([p.model_dump() for p in hyp.test_plan]),
                    hyp.assigned_worker_id,
                    hyp.generated_by_provider,
                    hyp.generated_by_model,
                    1 if hyp.is_fallback else 0,
                    hyp.fallback_reason,
                    json.dumps(hyp.metadata),
                    hyp.updated_at,
                    hyp.id,
                ),
            )
            await self.db.conn.commit()

        await self._emit("HYPOTHESIS_UPDATED", hyp.id, hyp.model_dump())

    async def get_hypothesis(self, hyp_id: str) -> Optional[Hypothesis]:
        """Fetch hypothesis by ID."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM hypotheses WHERE id = ?", (hyp_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            return self._row_to_hypothesis(row)

    async def list_hypotheses(self, status: Optional[HypothesisStatus] = None) -> List[Hypothesis]:
        """List hypotheses, optionally filtered by status, ordered by priority score descending."""
        async with self._lock:
            if status:
                cursor = await self.db.conn.execute(
                    "SELECT * FROM hypotheses WHERE status = ? ORDER BY priority_score DESC", (status.value,)
                )
            else:
                cursor = await self.db.conn.execute("SELECT * FROM hypotheses ORDER BY priority_score DESC")
            rows = await cursor.fetchall()
            return [self._row_to_hypothesis(r) for r in rows]

    def _row_to_hypothesis(self, row: aiosqlite.Row) -> Hypothesis:
        test_plan_raw = json.loads(row["test_plan"] or "[]")
        test_plan = [ProbeStep(**step) for step in test_plan_raw]
        keys = row.keys()
        req_acc = row["required_access_level"] if "required_access_level" in keys and row["required_access_level"] else None
        enb_acc = row["enables_access_level"] if "enables_access_level" in keys and row["enables_access_level"] else None
        return Hypothesis(
            id=row["id"],
            target_asset_id=row["target_asset_id"],
            category=row["category"],
            title=row["title"],
            description=row["description"] or "",
            supporting_observation_ids=json.loads(row["supporting_obs"] or "[]"),
            refuting_observation_ids=json.loads(row["refuting_obs"] or "[]"),
            prerequisite_hypothesis_ids=json.loads(row["prerequisite_hypotheses"] or "[]") if "prerequisite_hypotheses" in keys and row["prerequisite_hypotheses"] else [],
            required_access_level=AccessLevel(req_acc) if req_acc else AccessLevel.NONE,
            enables_access_level=AccessLevel(enb_acc) if enb_acc else None,
            stage=row["stage"] if "stage" in keys and row["stage"] is not None else 1,
            prior_probability=row["prior_prob"],
            confidence=row["confidence"],
            priority_score=row["priority_score"],
            status=row["status"],
            test_plan=test_plan,
            assigned_worker_id=row["assigned_worker_id"],
            generated_by_provider=row["generated_by_provider"] if "generated_by_provider" in keys else "unknown",
            generated_by_model=row["generated_by_model"] if "generated_by_model" in keys else "unknown",
            is_fallback=bool(row["is_fallback"]) if "is_fallback" in keys else False,
            fallback_reason=row["fallback_reason"] if "fallback_reason" in keys else None,
            metadata=json.loads(row["metadata"] or "{}"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ---------------- Attack Path Operations ----------------

    async def add_attack_path(self, path: AttackPath) -> None:
        """Insert or update a multi-stage attack path."""
        path.updated_at = _now_iso()
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO attack_paths (
                    id, name, source_asset_id, target_asset_id, asset_sequence, hypothesis_sequence,
                    path_status, path_confidence, path_uncertainty, risk_level, is_cycle_detected,
                    blocked_step_id, canary_target, description, metadata, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    source_asset_id=excluded.source_asset_id,
                    target_asset_id=excluded.target_asset_id,
                    asset_sequence=excluded.asset_sequence,
                    hypothesis_sequence=excluded.hypothesis_sequence,
                    path_status=excluded.path_status,
                    path_confidence=excluded.path_confidence,
                    path_uncertainty=excluded.path_uncertainty,
                    risk_level=excluded.risk_level,
                    is_cycle_detected=excluded.is_cycle_detected,
                    blocked_step_id=excluded.blocked_step_id,
                    canary_target=excluded.canary_target,
                    description=excluded.description,
                    metadata=excluded.metadata,
                    updated_at=excluded.updated_at
                """,
                (
                    path.path_id,
                    path.name,
                    path.source_asset_id,
                    path.target_asset_id,
                    json.dumps(path.asset_sequence),
                    json.dumps(path.hypothesis_sequence),
                    path.path_status.value if hasattr(path.path_status, "value") else str(path.path_status),
                    path.path_confidence,
                    path.path_uncertainty,
                    path.risk_level.value if hasattr(path.risk_level, "value") else str(path.risk_level),
                    1 if path.is_cycle_detected else 0,
                    path.blocked_step_id,
                    path.canary_target,
                    path.description,
                    json.dumps(path.metadata),
                    path.updated_at,
                ),
            )
            await self.db.conn.commit()

        await self._emit("ATTACK_PATH_RECORDED", path.path_id, path.model_dump())

    async def update_attack_path(self, path: AttackPath) -> None:
        """Convenience alias for add_attack_path."""
        await self.add_attack_path(path)

    async def get_attack_path(self, path_id: str) -> Optional[AttackPath]:
        """Fetch an attack path by its ID."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM attack_paths WHERE id = ?", (path_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            return self._row_to_attack_path(row)

    async def list_attack_paths(self, status: Optional[PathStatus] = None) -> List[AttackPath]:
        """List attack paths, optionally filtered by status, ordered by path_confidence DESC."""
        async with self._lock:
            if status:
                val = status.value if hasattr(status, "value") else str(status)
                cursor = await self.db.conn.execute(
                    "SELECT * FROM attack_paths WHERE path_status = ? ORDER BY path_confidence DESC", (val,)
                )
            else:
                cursor = await self.db.conn.execute("SELECT * FROM attack_paths ORDER BY path_confidence DESC")
            rows = await cursor.fetchall()
            return [self._row_to_attack_path(r) for r in rows]

    async def delete_attack_path(self, path_id: str) -> None:
        """Delete an attack path from state."""
        async with self._lock:
            await self.db.conn.execute("DELETE FROM attack_paths WHERE id = ?", (path_id,))
            await self.db.conn.commit()
        await self._emit("ATTACK_PATH_DELETED", path_id, {})

    def _row_to_attack_path(self, row: aiosqlite.Row) -> AttackPath:
        keys = row.keys()
        return AttackPath(
            path_id=row["id"],
            name=row["name"],
            source_asset_id=row["source_asset_id"],
            target_asset_id=row["target_asset_id"],
            asset_sequence=json.loads(row["asset_sequence"] or "[]"),
            hypothesis_sequence=json.loads(row["hypothesis_sequence"] or "[]"),
            path_status=PathStatus(row["path_status"]),
            path_confidence=float(row["path_confidence"]),
            path_uncertainty=float(row["path_uncertainty"]),
            risk_level=PathRisk(row["risk_level"]),
            is_cycle_detected=bool(row["is_cycle_detected"]),
            blocked_step_id=row["blocked_step_id"] if "blocked_step_id" in keys else None,
            canary_target=row["canary_target"] if "canary_target" in keys else None,
            description=row["description"] if ("description" in keys and row["description"]) else "",
            metadata=json.loads(row["metadata"] or "{}"),
            updated_at=row["updated_at"],
        )

    # ---------------- Evidence Operations ----------------

    async def add_evidence(self, ev: EvidenceRecord) -> None:
        """Store verifiable evidence."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO evidence (
                    id, hypothesis_id, step_id, worker_id, evidence_type, raw_data,
                    content_hash, supports, validation_power, falsification_power,
                    interpretation, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    ev.id,
                    ev.hypothesis_id,
                    ev.step_id,
                    ev.worker_id,
                    ev.evidence_type.value,
                    json.dumps(ev.raw_data),
                    ev.content_hash,
                    1 if ev.supports_hypothesis else 0,
                    ev.validation_power,
                    ev.falsification_power,
                    ev.interpretation,
                    ev.timestamp,
                ),
            )
            await self.db.conn.commit()

        await self._emit("EVIDENCE_ADDED", ev.id, ev.model_dump())

    async def list_evidence(self, hypothesis_id: Optional[str] = None) -> List[EvidenceRecord]:
        """List all evidence or evidence for a specific hypothesis."""
        async with self._lock:
            if hypothesis_id:
                cursor = await self.db.conn.execute(
                    "SELECT * FROM evidence WHERE hypothesis_id = ? ORDER BY timestamp ASC", (hypothesis_id,)
                )
            else:
                cursor = await self.db.conn.execute("SELECT * FROM evidence ORDER BY timestamp ASC")
            rows = await cursor.fetchall()
            return [
                EvidenceRecord(
                    id=r["id"],
                    hypothesis_id=r["hypothesis_id"],
                    step_id=r["step_id"],
                    worker_id=r["worker_id"],
                    evidence_type=r["evidence_type"],
                    raw_data=json.loads(r["raw_data"] or "{}"),
                    content_hash=r["content_hash"],
                    supports_hypothesis=bool(r["supports"]),
                    validation_power=r["validation_power"],
                    falsification_power=r["falsification_power"],
                    interpretation=r["interpretation"] or "",
                    timestamp=r["timestamp"],
                )
                for r in rows
            ]

    # ---------------- Failure & Lesson Operations ----------------

    async def add_failure(self, failure: FailureRecord) -> None:
        """Store a failure record."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO failures (id, hypothesis_id, worker_id, failure_category, error_message, diagnostic_details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    failure.id,
                    failure.hypothesis_id,
                    failure.worker_id,
                    failure.failure_category.value,
                    failure.error_message,
                    json.dumps(failure.diagnostic_details),
                    failure.timestamp,
                ),
            )
            await self.db.conn.commit()

        await self._emit("FAILURE_RECORDED", failure.id, failure.model_dump())

    async def list_failures(self, hypothesis_id: Optional[str] = None) -> List[FailureRecord]:
        """List failure records."""
        async with self._lock:
            if hypothesis_id:
                cursor = await self.db.conn.execute(
                    "SELECT * FROM failures WHERE hypothesis_id = ? ORDER BY timestamp ASC", (hypothesis_id,)
                )
            else:
                cursor = await self.db.conn.execute("SELECT * FROM failures ORDER BY timestamp ASC")
            rows = await cursor.fetchall()
            return [
                FailureRecord(
                    id=r["id"],
                    hypothesis_id=r["hypothesis_id"],
                    worker_id=r["worker_id"],
                    failure_category=r["failure_category"],
                    error_message=r["error_message"],
                    diagnostic_details=json.loads(r["diagnostic_details"] or "{}"),
                    timestamp=r["timestamp"],
                )
                for r in rows
            ]

    async def add_lesson(self, lesson: FailureLesson) -> None:
        """Store a failure lesson."""
        async with self._lock:
            await self.db.conn.execute(
                """
                INSERT INTO lessons (id, source_failure_id, target_asset_id, affected_category, penalty_factor, rule_description, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    lesson.id,
                    lesson.source_failure_id,
                    lesson.target_asset_id,
                    lesson.affected_category.value if lesson.affected_category else None,
                    lesson.penalty_factor,
                    lesson.rule_description,
                    1 if lesson.active else 0,
                    lesson.created_at,
                ),
            )
            await self.db.conn.commit()

        await self._emit("LESSON_LEARNED", lesson.id, lesson.model_dump())

    async def list_lessons(self, active_only: bool = True) -> List[FailureLesson]:
        """List failure lessons."""
        async with self._lock:
            if active_only:
                cursor = await self.db.conn.execute("SELECT * FROM lessons WHERE active = 1")
            else:
                cursor = await self.db.conn.execute("SELECT * FROM lessons")
            rows = await cursor.fetchall()
            return [
                FailureLesson(
                    id=r["id"],
                    source_failure_id=r["source_failure_id"],
                    target_asset_id=r["target_asset_id"],
                    affected_category=r["affected_category"],
                    penalty_factor=r["penalty_factor"],
                    rule_description=r["rule_description"],
                    active=bool(r["active"]),
                    created_at=r["created_at"],
                )
                for r in rows
            ]

    async def list_history(self) -> List[Dict[str, Any]]:
        """Retrieve audit history log."""
        async with self._lock:
            cursor = await self.db.conn.execute("SELECT * FROM history ORDER BY id ASC")
            rows = await cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "event_type": r["event_type"],
                    "entity_id": r["entity_id"],
                    "payload": json.loads(r["payload"] or "{}"),
                    "timestamp": r["timestamp"],
                }
                for r in rows
            ]
