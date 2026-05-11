from rest_framework.throttling import UserRateThrottle


class OSINTThrottle(UserRateThrottle):
    scope = "osint"


class AIThrottle(UserRateThrottle):
    scope = "ai"


class ExportThrottle(UserRateThrottle):
    scope = "export"
