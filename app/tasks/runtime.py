import asyncio

_TASK_LOOP = None


def get_task_loop():
    global _TASK_LOOP
    if _TASK_LOOP is None or _TASK_LOOP.is_closed():
        _TASK_LOOP = asyncio.new_event_loop()
    asyncio.set_event_loop(_TASK_LOOP)
    return _TASK_LOOP


def run_async_task(coro):
    loop = get_task_loop()
    return loop.run_until_complete(coro)
