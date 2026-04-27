from pydantic import BaseModel, field_validator


class RemediationDecisionRequest(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("Reason is required.")
        return reason
