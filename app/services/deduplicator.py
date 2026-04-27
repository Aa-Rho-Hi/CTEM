import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.entities import Vulnerability


class DeduplicatorService:
    @staticmethod
    def fingerprint(cve_id: str, asset_ip: str, source_tool: str, port: int | None) -> str:
        material = f"{cve_id}{asset_ip}{source_tool}{port or ''}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    async def upsert_duplicate(
        self,
        session,
        *,
        tenant_id,
        cve_id: str,
        asset_ip: str,
        source_tool: str,
        port: int | None,
        confidence_score: int,
    ) -> Vulnerability | None:
        fingerprint_hash = self.fingerprint(cve_id, asset_ip, source_tool, port)
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        statement = select(Vulnerability).where(
            Vulnerability.fingerprint_hash == fingerprint_hash,
            Vulnerability.last_seen >= cutoff,
        )
        existing = (await session.execute(statement)).scalar_one_or_none()
        if existing is None:
            return None
        existing.last_seen = datetime.now(timezone.utc)
        existing.confidence_score = confidence_score
        await session.flush()
        return existing

    async def bulk_check_and_update(
        self,
        session,
        records: list[tuple[str, int]],  # (fingerprint_hash, confidence_score)
    ) -> set[str]:
        """
        Check for existing vulnerabilities matching the given fingerprints and update them.
        Returns the set of fingerprint_hashes that are duplicates (found in DB).
        Performs one SELECT and one flush instead of N queries.
        """
        if not records:
            return set()
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        fp_to_score = {fp: score for fp, score in records}
        existing = (
            await session.execute(
                select(Vulnerability).where(
                    Vulnerability.fingerprint_hash.in_(list(fp_to_score.keys())),
                    Vulnerability.last_seen >= cutoff,
                )
            )
        ).scalars().all()
        now = datetime.now(timezone.utc)
        duplicate_fps: set[str] = set()
        for vuln in existing:
            vuln.last_seen = now
            vuln.confidence_score = fp_to_score[vuln.fingerprint_hash]
            duplicate_fps.add(vuln.fingerprint_hash)
        if duplicate_fps:
            await session.flush()
        return duplicate_fps

