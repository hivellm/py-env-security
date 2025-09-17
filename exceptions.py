"""
Custom exceptions for the secure script execution environment.
"""

class SecurityException(Exception):
    """Base exception for security-related errors."""
    pass

class ResourceLimitException(SecurityException):
    """Raised when a script exceeds resource limits."""
    pass

class FileSystemViolationException(SecurityException):
    """Raised when a script violates filesystem restrictions."""
    pass

class NetworkViolationException(SecurityException):
    """Raised when a script violates network restrictions."""
    pass

class PolicyViolationException(SecurityException):
    """Raised when a script violates security policy."""
    pass

class TimeoutException(SecurityException):
    """Raised when a script exceeds the execution timeout."""
    pass

class ScriptExecutionException(SecurityException):
    """Raised when script execution fails for security reasons."""
    pass
