class ChangeWindowBlockedError(RuntimeError):
    def __init__(self, zone_name: str, window_start: str, window_end: str):
        self.zone_name = zone_name
        self.window_start = window_start
        self.window_end = window_end
        super().__init__(f"Execution blocked for zone {zone_name}. Allowed window: {window_start}-{window_end}")


class NotApprovedError(RuntimeError):
    pass


class MissingApprovalAuditError(RuntimeError):
    pass


class ROENotFoundError(ValueError):
    pass


class ROEExpiredError(ValueError):
    pass


class OutOfScopeError(ValueError):
    def __init__(self, ip: str, cidr: str):
        super().__init__(f"{ip} is outside authorized scope {cidr}")
        self.ip = ip
        self.cidr = cidr


class InvalidIPError(ValueError):
    def __init__(self, value: str):
        super().__init__(f"Invalid IP or CIDR: {value}")


class TenantBoundaryViolationError(PermissionError):
    pass


class CrownJewelLockError(PermissionError):
    pass


class ToolNotWhitelistedError(PermissionError):
    def __init__(self, tool: str, whitelist: list):
        super().__init__(f"Tool '{tool}' not in whitelist: {whitelist}")
        self.tool = tool
        self.whitelist = whitelist


class ConfidenceBelowCeilingError(PermissionError):
    def __init__(self, score: int, ceiling: int):
        super().__init__(f"Confidence {score} below safety ceiling {ceiling}")
        self.score = score
        self.ceiling = ceiling
