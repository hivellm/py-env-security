"""
Secure Script Execution Environment for CMMV-Hive.

This package provides a sandboxed environment for executing Python scripts
with comprehensive security controls, resource limits, and audit logging.
"""

from .executor import SecureScriptExecutor
from policy import SecurityPolicy
from audit import AuditLogger
from monitor import SecurityMonitor
from analyzer import SecurityAnalyzer
from exceptions import (
    SecurityException,
    ResourceLimitException,
    FileSystemViolationException,
    NetworkViolationException,
    PolicyViolationException,
    TimeoutException,
    ScriptExecutionException
)

__version__ = "1.0.0"
__author__ = "Grok-Code-Fast-1"
__description__ = "Secure Script Execution Environment for CMMV-Hive"

__all__ = [
    'SecureScriptExecutor',
    'SecurityPolicy',
    'AuditLogger',
    'SecurityMonitor',
    'SecurityAnalyzer',
    'SecurityException',
    'ResourceLimitException',
    'FileSystemViolationException',
    'NetworkViolationException',
    'PolicyViolationException',
    'TimeoutException',
    'ScriptExecutionException'
]
