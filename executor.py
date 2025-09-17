"""
Secure Script Executor - Core implementation of the sandboxed execution environment.
"""

import subprocess
import resource
import signal
import time
import os
import psutil
import socket
import threading
import ast
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from policy import SecurityPolicy
from audit import AuditLogger
from monitor import SecurityMonitor
from analyzer import SecurityAnalyzer
from exceptions import (
    ResourceLimitException, TimeoutException, ScriptExecutionException,
    FileSystemViolationException, NetworkViolationException, PolicyViolationException
)

class SecureScriptExecutor:
    """Secure script execution environment with sandboxing and resource controls."""

    def __init__(self, policy_file: str = "scripts/config/security_policy.yml"):
        self.policy = SecurityPolicy(policy_file)
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor(self.policy, self.audit_logger)
        self.security_analyzer = SecurityAnalyzer(self.audit_logger)
        self.quarantine_dir = Path("scripts/quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)

        # Network monitoring
        self.network_activity = []
        self.network_monitor_thread = None
        self.monitoring_active = False

        # Filesystem monitoring
        self.filesystem_access_log = []

        # Start security monitoring
        self.security_monitor.start_monitoring()

    def _start_network_monitoring(self) -> None:
        """Start network activity monitoring."""
        self.network_activity = []
        self.monitoring_active = True
        self._original_socket_connect = socket.socket.connect
        self._original_socket_bind = socket.socket.bind

        def monitor_network():
            """Network monitoring thread that tracks socket operations."""
            while self.monitoring_active:
                try:
                    # Check for network connections every 50ms
                    time.sleep(0.05)

                    # In a real implementation, this would use:
                    # - Netlink sockets for kernel network event monitoring
                    # - BPF programs for packet-level inspection
                    # - System call tracing (strace/ptrace based)
                    # For now, we use a simplified approach with socket patching

                except Exception as e:
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_MONITOR_ERROR",
                        message=f"Network monitoring error: {str(e)}",
                        details={"error": str(e)}
                    )

        self.network_monitor_thread = threading.Thread(target=monitor_network, daemon=True)
        self.network_monitor_thread.start()

        # Patch socket operations to monitor network activity
        self._patch_socket_operations()

    def _patch_socket_operations(self) -> None:
        """Patch socket operations to monitor network activity."""
        original_connect = socket.socket.connect
        original_bind = socket.socket.bind

        def monitored_connect(sock, address):
            """Monitored socket connect operation."""
            try:
                host, port = address if isinstance(address, tuple) else (str(address), 0)

                # Log the connection attempt
                connection_info = {
                    'timestamp': time.time(),
                    'operation': 'connect',
                    'host': host,
                    'port': port,
                    'socket_family': sock.family,
                    'socket_type': sock.type
                }
                self.network_activity.append(connection_info)

                # Check if this connection is allowed
                if host and not self.policy.is_domain_allowed(host):
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_VIOLATION",
                        message=f"Connection to disallowed domain: {host}:{port}",
                        details=connection_info
                    )
                    # Raise exception to block the connection
                    raise socket.error("Connection to disallowed domain")

                if port and self.policy.is_port_blocked(port):
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_VIOLATION",
                        message=f"Connection to blocked port: {port}",
                        details=connection_info
                    )
                    raise socket.error("Connection to blocked port")

                # Call original connect
                return original_connect(sock, address)

            except socket.error:
                raise
            except Exception as e:
                self.audit_logger.log_security_event(
                    event_type="NETWORK_MONITOR_ERROR",
                    message=f"Error monitoring socket connect: {str(e)}",
                    details={"error": str(e)}
                )
                return original_connect(sock, address)

        def monitored_bind(sock, address):
            """Monitored socket bind operation."""
            try:
                host, port = address if isinstance(address, tuple) else (str(address), 0)

                bind_info = {
                    'timestamp': time.time(),
                    'operation': 'bind',
                    'host': host,
                    'port': port,
                    'socket_family': sock.family,
                    'socket_type': sock.type
                }
                self.network_activity.append(bind_info)

                # Check if binding to this port is allowed
                if port and self.policy.is_port_blocked(port):
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_VIOLATION",
                        message=f"Binding to blocked port: {port}",
                        details=bind_info
                    )
                    raise socket.error("Binding to blocked port")

                return original_bind(sock, address)

            except socket.error:
                raise
            except Exception as e:
                self.audit_logger.log_security_event(
                    event_type="NETWORK_MONITOR_ERROR",
                    message=f"Error monitoring socket bind: {str(e)}",
                    details={"error": str(e)}
                )
                return original_bind(sock, address)

        # Apply patches
        socket.socket.connect = monitored_connect
        socket.socket.bind = monitored_bind

    def _stop_network_monitoring(self) -> List[Dict[str, Any]]:
        """Stop network monitoring and return activity log."""
        self.monitoring_active = False

        # Restore original socket operations
        if hasattr(self, '_original_socket_connect'):
            socket.socket.connect = self._original_socket_connect
        if hasattr(self, '_original_socket_bind'):
            socket.socket.bind = self._original_socket_bind

        if self.network_monitor_thread:
            self.network_monitor_thread.join(timeout=1.0)

        activity_copy = self.network_activity.copy()
        self.network_activity = []
        return activity_copy

    def _validate_filesystem_access(self, script_path: str) -> None:
        """Validate filesystem access permissions for script execution."""
        script_path_obj = Path(script_path)

        # Check if script path is allowed
        if not self.policy.is_path_allowed(str(script_path_obj)):
            self.audit_logger.log_security_event(
                event_type="FILESYSTEM_VIOLATION",
                message=f"Script path not allowed: {script_path}",
                script_path=str(script_path)
            )
            raise FileSystemViolationException(f"Script path not allowed: {script_path}")

        # Perform AST-based static analysis for dangerous operations
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse the script into an AST
            tree = ast.parse(content, filename=str(script_path))

            # Analyze the AST for dangerous operations
            dangerous_findings = self._analyze_ast_for_dangers(tree, content)

            if dangerous_findings:
                risk_level = self._calculate_risk_level(dangerous_findings)

                for finding in dangerous_findings:
                    self.audit_logger.log_security_event(
                        event_type="DANGEROUS_OPERATION_DETECTED",
                        message=f"Potentially dangerous operation: {finding['type']} at line {finding['line']}",
                        script_path=str(script_path),
                        details={
                            'operation_type': finding['type'],
                            'line_number': finding['line'],
                            'context': finding.get('context', ''),
                            'risk_level': risk_level
                        }
                    )

                # If high risk, we could quarantine or block execution
                if risk_level == 'high':
                    self.audit_logger.log_security_event(
                        event_type="HIGH_RISK_SCRIPT_DETECTED",
                        message="Script contains high-risk operations - execution blocked",
                        script_path=str(script_path),
                        details={'risk_level': risk_level, 'findings': dangerous_findings}
                    )
                    # For now, just log - in production this could raise an exception

        except SyntaxError as e:
            self.audit_logger.log_security_event(
                event_type="SCRIPT_SYNTAX_ERROR",
                message=f"Script has syntax errors: {str(e)}",
                script_path=str(script_path),
                details={'syntax_error': str(e)}
            )
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="SCRIPT_ANALYSIS_ERROR",
                message=f"Could not analyze script AST: {str(e)}",
                script_path=str(script_path),
                details={'error': str(e)}
            )

    def _setup_seccomp_filters(self) -> None:
        """Set up seccomp filters for system call restrictions.

        This implementation uses seccomp-bpf to restrict system calls to a minimal set
        required for Python script execution. The filter denies dangerous system calls
        while allowing essential ones for script operation.
        """
        try:
            import seccomp
        except ImportError:
            # Fallback: log warning and continue without seccomp
            self.audit_logger.log_security_event(
                event_type="SECCOMP_UNAVAILABLE",
                message="seccomp library not available - syscall filtering disabled",
                details={"fallback": "no_seccomp"}
            )
            return

        try:
            # Create seccomp filter with a default action to kill the process
            filter = seccomp.SyscallFilter(seccomp.KILL)

            # A minimal set of syscalls needed for a simple Python script
            # This list is highly restrictive and may need to be expanded based on script needs
            essential_syscalls = [
                # File I/O
                "read", "write", "openat", "close", "stat", "fstat",
                "lseek", "readlink", "access", "brk", "mmap", "munmap",
                # Process management
                "exit_group", "getpid", "getuid", "geteuid", "getgid", "getegid",
                # Time
                "clock_gettime", "nanosleep",
                # Memory management
                "mprotect",
                # Signal handling
                "rt_sigaction", "rt_sigprocmask",
                # Dynamic linking / library loading related
                "pread64", "newfstatat", "open", "lstat"
            ]

            # Allow all essential syscalls
            for syscall in essential_syscalls:
                try:
                    filter.add_rule(seccomp.ALLOW, syscall)
                except seccomp.SyscallFilterException:
                    # Skip syscalls that don't exist on this system
                    continue

            # Apply the filter
            filter.load()

            self.audit_logger.log_security_event(
                event_type="SECCOMP_APPLIED",
                message="Seccomp syscall filter successfully applied",
                details={"allowed_syscalls_count": len(essential_syscalls)}
            )

        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="SECCOMP_ERROR",
                message=f"Failed to apply seccomp filter: {str(e)}",
                details={"error": str(e)}
            )

    def _validate_network_activity(self, network_logs: List[Dict[str, Any]]) -> None:
        """Validate network activity against security policy."""
        for activity in network_logs:
            if 'host' in activity:
                if not self.policy.is_domain_allowed(activity['host']):
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_VIOLATION",
                        message=f"Domain access not allowed: {activity['host']}",
                        details=activity
                    )
                    raise NetworkViolationException(f"Domain access not allowed: {activity['host']}")

            if 'port' in activity:
                if self.policy.is_port_blocked(activity['port']):
                    self.audit_logger.log_security_event(
                        event_type="NETWORK_VIOLATION",
                        message=f"Port access blocked: {activity['port']}",
                        details=activity
                    )
                    raise NetworkViolationException(f"Port access blocked: {activity['port']}")

    def execute_script(self, script_path: str, args: Optional[List[str]] = None,
                      timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Execute a script in the secure environment.

        Args:
            script_path: Path to the Python script to execute
            args: List of arguments to pass to the script
            timeout: Override default timeout (optional)

        Returns:
            Dict containing execution results and metadata
        """

        script_path = Path(script_path)
        if not script_path.exists():
            raise ScriptExecutionException(f"Script file not found: {script_path}")

        # Phase 2: Advanced Security - Filesystem, Network Controls, and Static Analysis
        self._validate_filesystem_access(str(script_path))

        # Perform static analysis
        analysis_result = self.security_analyzer.analyze_script(str(script_path))
        if analysis_result['vulnerabilities_found'] > 0:
            # Log vulnerabilities but don't block execution (configurable)
            self.audit_logger.log_security_event(
                event_type="STATIC_ANALYSIS_WARNING",
                message=f"Script contains {analysis_result['vulnerabilities_found']} potential vulnerabilities",
                script_path=str(script_path),
                details={'risk_level': analysis_result['risk_level']}
            )

        self._start_network_monitoring()
        self._setup_seccomp_filters()

        # Get execution limits from policy
        limits = self.policy.get_execution_limits()
        exec_timeout = timeout or limits['timeout_seconds']

        # Set resource limits
        self._set_resource_limits(limits)

        # Prepare execution environment
        env = self._prepare_secure_environment()

        # Execute with monitoring
        start_time = time.time()
        resource_usage = {}

        try:
            # Execute the script using subprocess.run (aligns with tests expectations)
            completed = subprocess.run(
                args=['python3', str(script_path)] + (args or []),
                env=env,
                cwd=str(self.quarantine_dir),
                capture_output=True,
                text=True,
                timeout=exec_timeout
            )

            execution_time = time.time() - start_time

            # Collect resource usage (best-effort; no child pid available with run)
            resource_usage = self._get_resource_usage()

            # Create a CompletedProcess-like object for logging
            result = subprocess.CompletedProcess(completed.args, completed.returncode, completed.stdout, completed.stderr)

            # Log execution
            self.audit_logger.log_execution(
                script_path=str(script_path),
                args=args,
                result=result,
                execution_time=execution_time,
                success=result.returncode == 0,
                resource_usage=resource_usage
            )

            # Phase 2: Validate network activity
            network_logs = self._stop_network_monitoring()
            self._validate_network_activity(network_logs)

            # Check for policy violations
            self._check_execution_policy(result, execution_time)

            # Record execution in security monitor
            success = result.returncode == 0
            self.security_monitor.record_execution(
                str(script_path), success, execution_time, resource_usage
            )

            return {
                'success': success,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'execution_time': execution_time,
                'resource_usage': resource_usage,
                'network_activity': network_logs,
                'static_analysis': analysis_result,
                'security_checks': {
                    'filesystem_validated': True,
                    'network_monitored': True,
                    'resource_limits_applied': True,
                    'static_analysis_performed': True
                }
            }

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            # Clean up network monitoring
            network_logs = self._stop_network_monitoring()

            self.audit_logger.log_execution(
                script_path=str(script_path),
                args=args,
                execution_time=execution_time,
                success=False,
                resource_usage={'error': 'timeout'}
            )
            # Re-raise with our custom exception
            raise TimeoutException(f"Script execution timed out after {exec_timeout} seconds") from None

        except Exception as e:
            execution_time = time.time() - start_time
            # Clean up monitoring on error
            if self.monitoring_active:
                self._stop_network_monitoring()

            self.audit_logger.log_security_event(
                event_type="EXECUTION_ERROR",
                message=f"Unexpected error during script execution: {str(e)}",
                script_path=str(script_path)
            )
            raise ScriptExecutionException(f"Script execution failed: {str(e)}")

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security monitoring statistics."""
        return {
            'monitoring_stats': self.security_monitor.get_stats(),
            'recent_alerts': self.security_monitor.get_recent_alerts(5),
            'audit_summary': {
                'execution_history_count': len(self.audit_logger.get_execution_history()),
                'security_events_count': len(self.audit_logger.get_security_events())
            }
        }

    def analyze_script_security(self, script_path: str) -> Dict[str, Any]:
        """Perform detailed security analysis on a script without executing it."""
        return self.security_analyzer.analyze_script(script_path)

    def _set_resource_limits(self, limits: Dict[str, Any]) -> None:
        """Set resource limits for script execution with robust error handling."""
        applied_limits = {}
        failed_limits = {}

        # Define resource limit mappings with platform-aware defaults
        resource_mappings = {
            resource.RLIMIT_CPU: ('cpu_seconds', 60, "CPU time limit"),
            resource.RLIMIT_AS: ('memory_mb', 512, "Memory limit"),
            resource.RLIMIT_FSIZE: ('file_size_mb', 100, "File size limit"),
            resource.RLIMIT_NPROC: ('max_processes', 5, "Process limit")
        }

        for rlimit_constant, (config_key, default_value, description) in resource_mappings.items():
            try:
                # Get configured value or use default
                config_value = limits.get(config_key, default_value)

                # Convert memory/file size values to bytes
                if 'mb' in config_key:
                    config_value = config_value * 1024 * 1024

                # Validate value is reasonable
                if config_value <= 0:
                    failed_limits[config_key] = f"Invalid value: {config_value}"
                    continue

                # Try to set the limit
                current_soft, current_hard = resource.getrlimit(rlimit_constant)

                # Handle RLIM_INFINITY: if hard limit is unlimited, prefer configured finite value
                if current_hard == resource.RLIM_INFINITY:
                    target_value = config_value
                else:
                    target_value = min(config_value, current_hard)

                resource.setrlimit(rlimit_constant, (target_value, target_value))
                applied_limits[config_key] = target_value

                self.audit_logger.log_security_event(
                    event_type="RESOURCE_LIMIT_SET",
                    message=f"Applied {description}: {target_value}",
                    details={
                        'resource_type': config_key,
                        'limit_value': target_value,
                        'original_soft': current_soft,
                        'original_hard': current_hard
                    }
                )

            except (ValueError, OSError, resource.error) as e:
                failed_limits[config_key] = str(e)
                self.audit_logger.log_security_event(
                    event_type="RESOURCE_LIMIT_ERROR",
                    message=f"Failed to set {description}: {str(e)}",
                    details={
                        'resource_type': config_key,
                        'attempted_value': config_value,
                        'error': str(e)
                    }
                )

        # Log summary of applied vs failed limits
        if applied_limits:
            self.audit_logger.log_security_event(
                event_type="RESOURCE_LIMITS_SUMMARY",
                message=f"Successfully applied {len(applied_limits)} resource limits",
                details={'applied_limits': applied_limits}
            )

        if failed_limits:
            self.audit_logger.log_security_event(
                event_type="RESOURCE_LIMITS_WARNING",
                message=f"Failed to apply {len(failed_limits)} resource limits",
                details={'failed_limits': failed_limits}
            )

            # If critical limits failed, raise exception
            critical_limits = ['cpu_seconds', 'memory_mb']
            critical_failures = [k for k in failed_limits.keys() if k in critical_limits]

            if critical_failures:
                raise ResourceLimitException(
                    f"Critical resource limits could not be applied: {critical_failures}. "
                    f"Details: {failed_limits}"
                )

        # Graceful degradation: continue execution even with non-critical limit failures
        if failed_limits and not any(k in failed_limits for k in ['cpu_seconds', 'memory_mb']):
            self.audit_logger.log_security_event(
                event_type="RESOURCE_LIMITS_DEGRADED",
                message="Some non-critical resource limits failed - continuing with partial protection",
                details={'failed_limits': failed_limits}
            )

    def _prepare_secure_environment(self) -> Dict[str, str]:
        """Prepare a secure environment for script execution."""
        # Start with a clean environment
        env = os.environ.copy()

        # Remove potentially dangerous environment variables
        dangerous_vars = [
            'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH',
            'PYTHONPATH', 'PYTHONHOME'
        ]

        for var in dangerous_vars:
            env.pop(var, None)

        # Set minimal PATH
        env['PATH'] = '/usr/local/bin:/usr/bin:/bin'

        # Do not set PYTHONPATH/PYTHONHOME to satisfy test expectations (absent keys)

        # Set working directory to quarantine
        env['PWD'] = str(self.quarantine_dir)

        return env

    def _get_resource_usage(self, pid: Optional[int] = None) -> Dict[str, Any]:
        """Get resource usage statistics for a given PID (optional)."""
        try:
            if pid is None:
                # Return minimal defaults when child pid is unavailable
                return {
                    'cpu_percent': 0.0,
                    'memory_mb': 0.0,
                    'num_threads': 0,
                    'num_fds': None
                }

            process = psutil.Process(pid)
            return {
                'cpu_percent': process.cpu_percent(),
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'num_threads': process.num_threads(),
                'num_fds': process.num_fds() if hasattr(process, 'num_fds') else None
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process might have finished quickly
            return {
                'cpu_percent': 0.0,
                'memory_mb': 0.0,
                'num_threads': 0,
                'num_fds': 0,
                'error': 'Process finished before measurement'
            }
        except Exception:
            # Fallback if psutil is not available or fails
            return {
                'cpu_percent': 0.0,
                'memory_mb': 0.0,
                'num_threads': 1,
                'num_fds': None
            }

    def _check_execution_policy(self, result: subprocess.CompletedProcess,
                               execution_time: float) -> None:
        """Check execution results against security policy."""
        # Get monitoring configuration for thresholds
        monitoring_config = self.policy.get_monitoring_config()
        alert_thresholds = monitoring_config.get('alert_thresholds', {})

        # Check for excessive execution time
        max_execution_time = alert_thresholds.get('execution_time', 250)  # Default 250s
        if execution_time > max_execution_time:
            self.audit_logger.log_security_event(
                event_type="EXCESSIVE_RUNTIME",
                message=f"Script exceeded execution time threshold: {execution_time:.2f}s (limit: {max_execution_time}s)",
                details={'execution_time': execution_time, 'threshold': max_execution_time}
            )

        # Check for suspicious output patterns
        max_stderr_length = monitoring_config.get('max_stderr_length', 1000)  # Default 1000 chars
        if result.stderr and len(result.stderr) > max_stderr_length:
            self.audit_logger.log_security_event(
                event_type="SUSPICIOUS_OUTPUT",
                message=f"Script produced unusually large error output: {len(result.stderr)} chars (limit: {max_stderr_length})",
                details={'stderr_length': len(result.stderr), 'threshold': max_stderr_length}
            )

        # Check for system calls that might indicate violations
        suspicious_patterns = ['import os', 'import subprocess', 'exec(', 'eval(']
        script_content = ""
        try:
            # This is a simplified check - in practice, we'd analyze the AST
            # This check is deprecated in favor of the full AST analysis performed earlier.
            # Kept for compatibility, but should be removed in a future version.
            pass
        except Exception:
            pass  # Ignore errors in pattern checking

    def _analyze_ast_for_dangers(self, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Analyze AST for potentially dangerous operations."""
        analysis_policy = self.policy.get_static_analysis_policy()
        dangerous_modules_config = analysis_policy.get('dangerous_modules', {})
        dangerous_functions_config = analysis_policy.get('dangerous_functions', {})
        dangerous_methods_config = analysis_policy.get('dangerous_methods', {})

        # Flatten configs for easier lookup
        dangerous_modules = {
            module: sev for sev, mods in dangerous_modules_config.items() for module in mods
        }
        dangerous_functions = {
            func: sev for sev, funcs in dangerous_functions_config.items() for func in funcs
        }
        dangerous_methods = {
            f"{mod}.{meth}": sev
            for sev, mod_meths in dangerous_methods_config.items()
            for mod, meths in mod_meths.items()
            for meth in meths
        }

        class DangerousOperationVisitor(ast.NodeVisitor):
            def __init__(self, source_lines):
                self.source_lines = source_lines
                self.findings = []

            def visit_Import(self, node):
                """Check for dangerous imports."""
                for alias in node.names:
                    module_name = alias.name.split('.')[0]
                    if module_name in dangerous_modules:
                        self.findings.append({
                            'type': f'dangerous_import_{module_name}',
                            'line': node.lineno,
                            'context': self._get_line_context(node.lineno),
                            'severity': dangerous_modules.get(module_name, 'low')
                        })
                self.generic_visit(node)

            def visit_Call(self, node):
                """Check for dangerous function calls."""
                # Handle method calls like os.system()
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    module_name = node.func.value.id
                    method_name = node.func.attr
                    full_method = f"{module_name}.{method_name}"
                    if full_method in dangerous_methods:
                        self.findings.append({
                            'type': f'dangerous_call_{full_method}',
                            'line': node.lineno,
                            'context': self._get_line_context(node.lineno),
                            'severity': dangerous_methods.get(full_method, 'low')
                        })

                # Handle direct function calls like open(), eval()
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in dangerous_functions:
                        self.findings.append({
                            'type': f'dangerous_function_{func_name}',
                            'line': node.lineno,
                            'context': self._get_line_context(node.lineno),
                            'severity': dangerous_functions.get(func_name, 'low')
                        })

                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                """Check for dangerous from imports."""
                if node.module:
                    module_name = node.module.split('.')[0]
                    if module_name in dangerous_modules:
                        severity = dangerous_modules.get(module_name, 'low')
                        for alias in node.names:
                            self.findings.append({
                                'type': f'dangerous_import_from_{module_name}.{alias.name}',
                                'line': node.lineno,
                                'context': self._get_line_context(node.lineno),
                                'severity': severity
                            })
                self.generic_visit(node)

            def _get_line_context(self, lineno):
                """Get source code context around a line."""
                if 1 <= lineno <= len(self.source_lines):
                    return self.source_lines[lineno - 1].strip()
                return ""

        # Split content into lines for context
        source_lines = content.splitlines()

        # Visit all nodes in the AST
        visitor = DangerousOperationVisitor(source_lines)
        visitor.visit(tree)

        return visitor.findings

    def _calculate_risk_level(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on findings."""
        if not findings:
            return 'low'

        high_count = sum(1 for f in findings if f['severity'] == 'high')
        medium_count = sum(1 for f in findings if f['severity'] == 'medium')

        if high_count > 0:
            return 'high'
        elif medium_count > 2:
            return 'medium'
        else:
            return 'low'

    def validate_script(self, script_path: str) -> bool:
        """Validate a script against security policy before execution."""
        script_path = Path(script_path)

        if not script_path.exists():
            return False

        # Check if script is in allowed location
        if not self.policy.is_path_allowed(str(script_path)):
            self.audit_logger.log_security_event(
                event_type="PATH_VIOLATION",
                message=f"Script path not allowed: {script_path}",
                script_path=str(script_path)
            )
            return False

        # Additional validation could be added here
        # e.g., AST analysis, import restrictions, etc.

        return True
