from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(alias="DATABASE_URL")
    redis_url: str = Field(alias="REDIS_URL")
    jwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(alias="JWT_EXPIRE_MINUTES")

    openai_api_key: str = Field(alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", alias="OPENAI_MODEL")
    openai_base_url: str = Field(default="https://api.openai.com/openai", alias="OPENAI_BASE_URL")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")

    nvd_api_key: str = Field(alias="NVD_API_KEY")
    nist_nvd_base_url: str = Field(alias="NIST_NVD_BASE_URL")

    tanium_url: str = Field(alias="TANIUM_URL")
    tanium_api_key: str = Field(alias="TANIUM_API_KEY")
    servicenow_url: str = Field(alias="SERVICENOW_URL")
    servicenow_user: str = Field(alias="SERVICENOW_USER")
    servicenow_pass: str = Field(alias="SERVICENOW_PASS")
    jira_url: str = Field(alias="JIRA_URL")
    jira_api_key: str = Field(alias="JIRA_API_KEY")
    splunk_url: str = Field(alias="SPLUNK_URL")
    splunk_token: str = Field(alias="SPLUNK_TOKEN")

    neo4j_url: str = Field(alias="NEO4J_URL")
    neo4j_user: str = Field(alias="NEO4J_USER")
    neo4j_password: str = Field(alias="NEO4J_PASSWORD")

    environment: Literal["development", "staging", "production"] = Field(alias="ENVIRONMENT")
    log_level: str = Field(alias="LOG_LEVEL")

    @field_validator(
        "jwt_secret_key",
        "openai_api_key",
        "nvd_api_key",
        "tanium_api_key",
        "servicenow_pass",
        "jira_api_key",
        "splunk_token",
        "neo4j_password",
    )
    @classmethod
    def validate_non_empty_secret(cls, value: str) -> str:
        if not value:
            raise ValueError("Required secret is missing.")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
