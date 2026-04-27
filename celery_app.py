from celery import Celery
from celery.schedules import crontab
from kombu import Queue

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "atlas_ctem",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_pipeline",
        "app.tasks.risk_scoring",
        "app.tasks.compliance_update",
        "app.tasks.remediation_exec",
        "app.tasks.sla_monitor",
    ],
)
celery_app.conf.beat_schedule = {
    "daily-external-attack-surface-discovery": {
        "task": "app.tasks.scan_pipeline.discover_external_attack_surface",
        "schedule": crontab(hour=3, minute=0),
        "args": ("00000000-0000-0000-0000-000000000001", {}),
    },
    "hourly-sla-monitor": {
        "task": "app.tasks.sla_monitor.monitor_all_tenant_slas",
        "schedule": crontab(minute=5),
    },
}
celery_app.conf.task_default_queue = "celery"
celery_app.conf.task_queues = (
    Queue("celery"),
    Queue("scoring"),
)
celery_app.conf.task_routes = {
    "app.tasks.risk_scoring.score_scan_findings": {"queue": "scoring"},
    "app.tasks.risk_scoring.rescore_vulnerability": {"queue": "scoring"},
}
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]
