"""Recoverable hypothesis ledger CRUD with optimistic revision locking.

Implements ``docs/08`` section 3 & section 5 (``hypothesis.update``):
maintains ``HypothesisRecord`` entries in SQLite with supporting/contradicting
evidence links, cross-run evidence isolation checks, and optimistic locking.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from ctf_mcp.contracts import (
    ActionConflictError,
    ContractViolationError,
    EvidenceAccessDeniedError,
    HypothesisRecord,
    HypothesisState,
    canonical_json,
)
from ctf_mcp.storage import Storage


def _normalize_utc(dt: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if dt is None else dt
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _dedupe_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in values:
        cleaned = item.strip()
        if not cleaned:
            raise ContractViolationError("Evidence IDs in hypothesis links cannot be empty.")
        if cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)
    return tuple(ordered)


def _row_to_hypothesis(row: sqlite3.Row) -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=str(row["hypothesis_id"]),
        run_id=str(row["run_id"]),
        claim=str(row["claim"]),
        state=HypothesisState(str(row["state"])),
        supporting_evidence_ids=tuple(json.loads(str(row["supporting_evidence_json"]))),
        contradicting_evidence_ids=tuple(json.loads(str(row["contradicting_evidence_json"]))),
        next_observation=str(row["next_observation"]),
        revision=int(row["revision"]),
        updated_at=_normalize_utc(datetime.fromisoformat(str(row["updated_at"]))),
    )


def _validate_evidence_links_in_tx(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    supporting: tuple[str, ...],
    contradicting: tuple[str, ...],
    require_existing_evidence: bool,
) -> None:
    overlap = set(supporting).intersection(contradicting)
    if overlap:
        raise ContractViolationError(
            "An evidence ID cannot be both supporting and contradicting on the same hypothesis.",
            details={"overlapping_evidence_ids": sorted(overlap)},
        )

    all_ids = supporting + contradicting
    if not all_ids:
        return

    for ev_id in all_ids:
        row = conn.execute(
            "SELECT run_id FROM evidence_objects WHERE evidence_id = ?",
            (ev_id,),
        ).fetchone()
        if row is None:
            if require_existing_evidence:
                raise ContractViolationError(
                    f"Referenced evidence {ev_id!r} does not exist for run {run_id!r}.",
                    details={"evidence_id": ev_id, "run_id": run_id},
                )
        elif str(row["run_id"]) != run_id:
            raise EvidenceAccessDeniedError(
                f"Cross-run evidence reference {ev_id!r} denied for run {run_id!r}.",
                details={"evidence_id": ev_id, "run_id": run_id},
            )


class HypothesisManager:
    """Manages recoverable hypothesis records per run in SQLite."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def create_hypothesis_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        claim: str,
        next_observation: str,
        state: HypothesisState = HypothesisState.UNKNOWN,
        supporting_evidence_ids: tuple[str, ...] = (),
        contradicting_evidence_ids: tuple[str, ...] = (),
        hypothesis_id: str | None = None,
        require_existing_evidence: bool = False,
        now: datetime | None = None,
    ) -> HypothesisRecord:
        """Create and persist a new HypothesisRecord for ``run_id``."""
        run_row = conn.execute(
            "SELECT closed_at FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise ContractViolationError(f"Run {run_id!r} does not exist.")

        sup = _dedupe_ids(supporting_evidence_ids)
        con = _dedupe_ids(contradicting_evidence_ids)
        _validate_evidence_links_in_tx(
            conn,
            run_id=run_id,
            supporting=sup,
            contradicting=con,
            require_existing_evidence=require_existing_evidence,
        )

        ts = _normalize_utc(now)
        hid = f"hyp-{uuid4().hex}" if hypothesis_id is None else hypothesis_id
        record = HypothesisRecord(
            hypothesis_id=hid,
            run_id=run_id,
            claim=claim,
            state=state,
            supporting_evidence_ids=sup,
            contradicting_evidence_ids=con,
            next_observation=next_observation,
            revision=1,
            updated_at=ts,
        )
        try:
            conn.execute(
                """
                INSERT INTO hypotheses (
                    hypothesis_id, run_id, claim, state,
                    supporting_evidence_json, contradicting_evidence_json,
                    next_observation, revision, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.hypothesis_id,
                    record.run_id,
                    record.claim,
                    record.state.value,
                    canonical_json(list(record.supporting_evidence_ids)),
                    canonical_json(list(record.contradicting_evidence_ids)),
                    record.next_observation,
                    record.revision,
                    ts.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ActionConflictError(
                f"Hypothesis {record.hypothesis_id!r} already exists."
            ) from exc
        return record

    def create_hypothesis(
        self,
        *,
        run_id: str,
        claim: str,
        next_observation: str,
        state: HypothesisState = HypothesisState.UNKNOWN,
        supporting_evidence_ids: tuple[str, ...] = (),
        contradicting_evidence_ids: tuple[str, ...] = (),
        hypothesis_id: str | None = None,
        require_existing_evidence: bool = False,
        now: datetime | None = None,
    ) -> HypothesisRecord:
        """Create a HypothesisRecord inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.create_hypothesis_in_tx(
                conn,
                run_id=run_id,
                claim=claim,
                next_observation=next_observation,
                state=state,
                supporting_evidence_ids=supporting_evidence_ids,
                contradicting_evidence_ids=contradicting_evidence_ids,
                hypothesis_id=hypothesis_id,
                require_existing_evidence=require_existing_evidence,
                now=now,
            )

    def get_hypothesis_in_tx(
        self,
        conn: sqlite3.Connection,
        hypothesis_id: str,
        *,
        run_id: str | None = None,
    ) -> HypothesisRecord:
        """Fetch a HypothesisRecord, optionally verifying it belongs to ``run_id``."""
        row = conn.execute(
            "SELECT * FROM hypotheses WHERE hypothesis_id = ?",
            (hypothesis_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Hypothesis {hypothesis_id!r} does not exist.",
                details={"hypothesis_id": hypothesis_id},
            )
        if run_id is not None and str(row["run_id"]) != run_id:
            raise EvidenceAccessDeniedError(
                f"Hypothesis {hypothesis_id!r} does not belong to run {run_id!r}.",
                details={"hypothesis_id": hypothesis_id, "run_id": run_id},
            )
        return _row_to_hypothesis(row)

    def get_hypothesis(
        self,
        hypothesis_id: str,
        *,
        run_id: str | None = None,
    ) -> HypothesisRecord:
        """Read-only fetch of a HypothesisRecord."""
        with self.storage.read_connection() as conn:
            return self.get_hypothesis_in_tx(conn, hypothesis_id, run_id=run_id)

    def list_hypotheses(self, run_id: str) -> list[HypothesisRecord]:
        """List all HypothesisRecords for ``run_id`` ordered by revision/update."""
        with self.storage.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE run_id = ? ORDER BY updated_at ASC, hypothesis_id ASC",
                (run_id,),
            ).fetchall()
            return [_row_to_hypothesis(r) for r in rows]

    def update_hypothesis_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        hypothesis_id: str,
        run_id: str,
        expected_revision: int,
        state: HypothesisState | None = None,
        claim: str | None = None,
        next_observation: str | None = None,
        supporting_evidence_ids: tuple[str, ...] | None = None,
        contradicting_evidence_ids: tuple[str, ...] | None = None,
        add_supporting_evidence_ids: tuple[str, ...] = (),
        add_contradicting_evidence_ids: tuple[str, ...] = (),
        require_existing_evidence: bool = False,
        now: datetime | None = None,
    ) -> HypothesisRecord:
        """Update an existing hypothesis with optimistic ``expected_revision`` locking."""
        current = self.get_hypothesis_in_tx(conn, hypothesis_id, run_id=run_id)
        if current.revision != expected_revision:
            raise ActionConflictError(
                f"Hypothesis {hypothesis_id!r} revision mismatch: "
                f"expected {expected_revision}, got {current.revision}.",
                details={
                    "hypothesis_id": hypothesis_id,
                    "expected_revision": expected_revision,
                    "actual_revision": current.revision,
                },
            )

        base_sup = (
            current.supporting_evidence_ids
            if supporting_evidence_ids is None
            else supporting_evidence_ids
        )
        base_con = (
            current.contradicting_evidence_ids
            if contradicting_evidence_ids is None
            else contradicting_evidence_ids
        )
        new_sup = _dedupe_ids(base_sup + add_supporting_evidence_ids)
        new_con = _dedupe_ids(base_con + add_contradicting_evidence_ids)

        _validate_evidence_links_in_tx(
            conn,
            run_id=run_id,
            supporting=new_sup,
            contradicting=new_con,
            require_existing_evidence=require_existing_evidence,
        )

        ts = _normalize_utc(now)
        updated = HypothesisRecord(
            hypothesis_id=current.hypothesis_id,
            run_id=current.run_id,
            claim=current.claim if claim is None else claim,
            state=current.state if state is None else state,
            supporting_evidence_ids=new_sup,
            contradicting_evidence_ids=new_con,
            next_observation=(
                current.next_observation if next_observation is None else next_observation
            ),
            revision=current.revision + 1,
            updated_at=ts,
        )

        cur = conn.execute(
            """
            UPDATE hypotheses
            SET claim = ?, state = ?,
                supporting_evidence_json = ?, contradicting_evidence_json = ?,
                next_observation = ?, revision = ?, updated_at = ?
            WHERE hypothesis_id = ? AND run_id = ? AND revision = ?
            """,
            (
                updated.claim,
                updated.state.value,
                canonical_json(list(updated.supporting_evidence_ids)),
                canonical_json(list(updated.contradicting_evidence_ids)),
                updated.next_observation,
                updated.revision,
                ts.isoformat(),
                hypothesis_id,
                run_id,
                expected_revision,
            ),
        )
        if cur.rowcount != 1:
            raise ActionConflictError(
                f"Concurrent update detected on hypothesis {hypothesis_id!r}."
            )
        return updated

    def update_hypothesis(
        self,
        *,
        hypothesis_id: str,
        run_id: str,
        expected_revision: int,
        state: HypothesisState | None = None,
        claim: str | None = None,
        next_observation: str | None = None,
        supporting_evidence_ids: tuple[str, ...] | None = None,
        contradicting_evidence_ids: tuple[str, ...] | None = None,
        add_supporting_evidence_ids: tuple[str, ...] = (),
        add_contradicting_evidence_ids: tuple[str, ...] = (),
        require_existing_evidence: bool = False,
        now: datetime | None = None,
    ) -> HypothesisRecord:
        """Update a HypothesisRecord inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.update_hypothesis_in_tx(
                conn,
                hypothesis_id=hypothesis_id,
                run_id=run_id,
                expected_revision=expected_revision,
                state=state,
                claim=claim,
                next_observation=next_observation,
                supporting_evidence_ids=supporting_evidence_ids,
                contradicting_evidence_ids=contradicting_evidence_ids,
                add_supporting_evidence_ids=add_supporting_evidence_ids,
                add_contradicting_evidence_ids=add_contradicting_evidence_ids,
                require_existing_evidence=require_existing_evidence,
                now=now,
            )


__all__ = ["HypothesisManager"]
