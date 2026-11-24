"""Enumerations for DiSSTROY data models."""

from enum import Enum


class AssetType(str, Enum):
    """Types of computational or organizational assets."""
    SERVICE = "SERVICE"
    HOST = "HOST"
    ENDPOINT = "ENDPOINT"
    DATABASE = "DATABASE"
    API_GATEWAY = "API_GATEWAY"
    AUTH_PROVIDER = "AUTH_PROVIDER"
    DATA_STORE = "DATA_STORE"
    INTERNAL_PROXY = "INTERNAL_PROXY"


class ObservationKind(str, Enum):
    """Types of structured observations collected from target systems."""
    PORT_BANNER = "PORT_BANNER"
    HTTP_HEADER = "HTTP_HEADER"
    CONFIG_LEAK = "CONFIG_LEAK"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"
    AUTH_SCHEME = "AUTH_SCHEME"
    VERSION_EXPOSURE = "VERSION_EXPOSURE"
    TRAFFIC_PATTERN = "TRAFFIC_PATTERN"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    ERROR_DISCLOSURE = "ERROR_DISCLOSURE"


class HypothesisCategory(str, Enum):
    """Categories of security hypotheses."""
    AUTH_BYPASS_RISK = "AUTH_BYPASS_RISK"
    UNRESTRICTED_ACCESS = "UNRESTRICTED_ACCESS"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    CONFIGURATION_DEFECT = "CONFIGURATION_DEFECT"
    PRIVILEGE_ESCALATION_RISK = "PRIVILEGE_ESCALATION_RISK"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"


class HypothesisStatus(str, Enum):
    """Lifecycle status of an investigation hypothesis."""
    PENDING = "PENDING"
    PROPOSED = "PROPOSED"
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    TESTING = "TESTING"
    VALIDATED = "VALIDATED"
    REFUTED = "REFUTED"
    ABANDONED = "ABANDONED"


class PathStatus(str, Enum):
    """Evaluation status of an attack path."""
    THEORETICAL = "THEORETICAL"
    FEASIBLE = "FEASIBLE"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


class AccessLevel(str, Enum):
    """Simulated access privilege level on an asset or path."""
    NONE = "NONE"
    PUBLIC = "PUBLIC"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    ADMIN_PRIVILEGE = "ADMIN_PRIVILEGE"
    DATABASE_ROOT = "DATABASE_ROOT"


class PathRisk(str, Enum):
    """Risk severity assigned to an attack path."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceType(str, Enum):
    """Classification of collected evidence."""
    PROBE_RESPONSE = "PROBE_RESPONSE"
    CONFIGURATION_DUMP = "CONFIGURATION_DUMP"
    DIFF_ANALYSIS = "DIFF_ANALYSIS"
    HEADER_ANALYSIS = "HEADER_ANALYSIS"
    LOG_RECORD = "LOG_RECORD"
    ERROR_TRACE = "ERROR_TRACE"


class FailureCategory(str, Enum):
    """Diagnostics category for an unsuccessful investigation."""
    PROBE_TIMEOUT = "PROBE_TIMEOUT"
    ACCESS_DENIED_HARD = "ACCESS_DENIED_HARD"
    COUNTERMEASURE_DETECTED = "COUNTERMEASURE_DETECTED"
    INVALID_PREMISE = "INVALID_PREMISE"
    PATCH_VERIFIED = "PATCH_VERIFIED"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"


class WorkerState(str, Enum):
    """State of an investigation worker."""
    IDLE = "IDLE"
    SPAWNED = "SPAWNED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class OrchestratorState(str, Enum):
    """Execution state of the central orchestrator."""
    INITIALIZING = "INITIALIZING"
    DISCOVERING = "DISCOVERING"
    INVESTIGATING = "INVESTIGATING"
    ADAPTING = "ADAPTING"
    CONVERGED = "CONVERGED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
