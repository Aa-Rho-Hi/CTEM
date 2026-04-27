from datetime import datetime, timezone

BREACHED = "breached"
BREACH_IN_12_HOURS = "breach_in_12_hours"
BREACH_IN_2_DAYS = "breach_in_2_days"
DUE_LATER = "due_later"


def ensure_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def compute_sla_window(sla_due_date: datetime, *, now: datetime | None = None) -> dict[str, object]:
    current = ensure_utc(now or datetime.now(timezone.utc))
    due = ensure_utc(sla_due_date)
    delta_seconds = (due - current).total_seconds()
    hours_remaining = round(delta_seconds / 3600, 1)

    if delta_seconds < 0:
        bucket = BREACHED
        window_label = "Breached SLA"
        countdown_label = f"Breached {abs(hours_remaining):.1f}h ago"
    elif delta_seconds <= 12 * 3600:
        bucket = BREACH_IN_12_HOURS
        window_label = "Breach In 12 Hours"
        countdown_label = f"Breaches in {hours_remaining:.1f}h"
    elif delta_seconds <= 48 * 3600:
        bucket = BREACH_IN_2_DAYS
        if delta_seconds <= 24 * 3600:
            window_label = "Breach In 1 Day"
            countdown_label = f"Breaches in {hours_remaining:.1f}h"
        else:
            window_label = "Breach In 2 Days"
            countdown_label = f"Breaches in {hours_remaining / 24:.1f}d"
    else:
        bucket = DUE_LATER
        window_label = "Due Later"
        countdown_label = f"Breaches in {hours_remaining / 24:.1f}d"

    return {
        "bucket": bucket,
        "window_label": window_label,
        "countdown_label": countdown_label,
        "hours_remaining": hours_remaining,
    }
