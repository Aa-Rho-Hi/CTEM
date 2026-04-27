from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import DateTime, MetaData, Uuid, event
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, declared_attr, mapped_column, with_loader_criteria

from app.config import get_settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(AsyncAttrs, DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class TenantMixin:
    @declared_attr.directive
    def tenant_id(cls) -> Mapped[Uuid]:
        return mapped_column(Uuid, nullable=False, index=True)


@lru_cache
def get_engine():
    settings = get_settings()
    return create_async_engine(settings.database_url, future=True, pool_pre_ping=True)


@lru_cache
def get_session_factory():
    return async_sessionmaker(bind=get_engine(), expire_on_commit=False, class_=AsyncSession)


def reset_async_db_state():
    get_session_factory.cache_clear()
    get_engine.cache_clear()


def get_scoped_session(tenant_id):
    return get_session_factory()(info={"tenant_id": tenant_id})


@lru_cache
def get_tenant_scoped_models():
    return tuple(
        mapper.class_
        for mapper in Base.registry.mappers
        if issubclass(mapper.class_, TenantMixin)
    )


@event.listens_for(Session, "do_orm_execute")
def _add_tenant_criteria(execute_state):
    tenant_id = execute_state.session.info.get("tenant_id")
    if tenant_id is None or not execute_state.is_select:
        return

    statement = execute_state.statement
    for model in get_tenant_scoped_models():
        statement = statement.options(
            with_loader_criteria(
                model,
                lambda cls, tenant_id=tenant_id: cls.tenant_id == tenant_id,
                include_aliases=True,
            )
        )
    execute_state.statement = statement


@event.listens_for(Session, "before_flush")
def _enforce_tenant_id(session, flush_context, instances):
    tenant_id = session.info.get("tenant_id")
    for instance in session.new:
        if isinstance(instance, TenantMixin):
            if tenant_id is None and getattr(instance, "tenant_id", None) is None:
                raise ValueError("Tenant-scoped write attempted without tenant context.")
            if tenant_id is not None:
                instance.tenant_id = tenant_id
    for instance in session.dirty:
        if instance.__class__.__name__ == "AuditLog":
            raise ValueError("Audit log records are immutable and cannot be updated.")
    for instance in session.deleted:
        if instance.__class__.__name__ == "AuditLog":
            raise ValueError("Audit log records are immutable and cannot be deleted.")
