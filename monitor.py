"""
Security monitoring and alerting system for the secure script execution environment.
"""

import time
import threading
from typing import Dict, Any, List, Callable, Optional
from audit import AuditLogger
from policy import SecurityPolicy

class SecurityMonitor:
    """Real-time security monitoring and alerting system."""

    def __init__(self, policy: SecurityPolicy, audit_logger: AuditLogger):
        self.policy = policy
        self.audit_logger = audit_logger
        self.alert_handlers: List[Callable[[str, Dict[str, Any]], None]] = []
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.alert_queue: List[Dict[str, Any]] = []
        self.stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'security_violations': 0,
            'alerts_sent': 0
        }

    def start_monitoring(self) -> None:
        """Start the security monitoring system."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop the security monitoring system."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)

    def add_alert_handler(self, handler: Callable[[str, Dict[str, Any]], None]) -> None:
        """Add an alert handler function."""
        self.alert_handlers.append(handler)

    def remove_alert_handler(self, handler: Callable[[str, Dict[str, Any]], None]) -> None:
        """Remove an alert handler function."""
        if handler in self.alert_handlers:
            self.alert_handlers.remove(handler)

    def record_execution(self, script_path: str, success: bool, execution_time: float,
                        resource_usage: Dict[str, Any]) -> None:
        """Record script execution for monitoring."""
        self.stats['total_executions'] += 1

        if success:
            self.stats['successful_executions'] += 1
        else:
            self.stats['failed_executions'] += 1

        # Check for alert conditions
        self._check_execution_alerts(script_path, success, execution_time, resource_usage)

    def record_security_event(self, event_type: str, message: str,
                            script_path: Optional[str] = None,
                            details: Optional[Dict[str, Any]] = None) -> None:
        """Record a security event."""
        self.stats['security_violations'] += 1

        # Create alert for security events
        alert = {
            'type': 'security_event',
            'event_type': event_type,
            'message': message,
            'script_path': script_path,
            'details': details or {},
            'timestamp': time.time()
        }

        self._queue_alert(alert)

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return self.stats.copy()

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        return self.alert_queue[-limit:] if self.alert_queue else []

    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.monitoring_active:
            # Process queued alerts
            self._process_alert_queue()

            # Check system health
            self._check_system_health()

            time.sleep(1.0)  # Check every second

    def _check_execution_alerts(self, script_path: str, success: bool,
                               execution_time: float, resource_usage: Dict[str, Any]) -> None:
        """Check for execution-related alerts."""
        # Check execution time threshold
        if execution_time > 250:  # Configurable threshold
            alert = {
                'type': 'performance_alert',
                'alert_type': 'excessive_execution_time',
                'script_path': script_path,
                'execution_time': execution_time,
                'threshold': 250,
                'timestamp': time.time()
            }
            self._queue_alert(alert)

        # Check resource usage
        if 'cpu_percent' in resource_usage:
            cpu_threshold = self.policy.get_monitoring_config().get('alert_thresholds', {}).get('cpu_usage', 80)
            if resource_usage['cpu_percent'] > cpu_threshold:
                alert = {
                    'type': 'resource_alert',
                    'alert_type': 'high_cpu_usage',
                    'script_path': script_path,
                    'cpu_percent': resource_usage['cpu_percent'],
                    'threshold': cpu_threshold,
                    'timestamp': time.time()
                }
                self._queue_alert(alert)

        # Check memory usage
        if 'memory_mb' in resource_usage:
            memory_threshold = self.policy.get_monitoring_config().get('alert_thresholds', {}).get('memory_usage', 90)
            # Note: This would need adjustment based on actual memory limits
            if resource_usage['memory_mb'] > 400:  # Simplified check
                alert = {
                    'type': 'resource_alert',
                    'alert_type': 'high_memory_usage',
                    'script_path': script_path,
                    'memory_mb': resource_usage['memory_mb'],
                    'threshold': memory_threshold,
                    'timestamp': time.time()
                }
                self._queue_alert(alert)

    def _check_system_health(self) -> None:
        """Check overall system health."""
        # Check if failure rate is too high
        if self.stats['total_executions'] > 10:
            failure_rate = self.stats['failed_executions'] / self.stats['total_executions']
            if failure_rate > 0.5:  # More than 50% failures
                alert = {
                    'type': 'system_alert',
                    'alert_type': 'high_failure_rate',
                    'failure_rate': failure_rate,
                    'total_executions': self.stats['total_executions'],
                    'failed_executions': self.stats['failed_executions'],
                    'timestamp': time.time()
                }
                self._queue_alert(alert)

    def _queue_alert(self, alert: Dict[str, Any]) -> None:
        """Queue an alert for processing."""
        self.alert_queue.append(alert)

        # Keep only last 100 alerts
        if len(self.alert_queue) > 100:
            self.alert_queue = self.alert_queue[-100:]

    def _process_alert_queue(self) -> None:
        """Process queued alerts."""
        while self.alert_queue:
            alert = self.alert_queue.pop(0)
            self.stats['alerts_sent'] += 1

            # Send to all registered handlers
            for handler in self.alert_handlers:
                try:
                    handler(alert['type'], alert)
                except Exception as e:
                    # Log handler errors but don't stop processing
                    print(f"Alert handler error: {e}")

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive monitoring report."""
        return {
            'timestamp': time.time(),
            'stats': self.get_stats(),
            'recent_alerts': self.get_recent_alerts(20),
            'system_health': {
                'monitoring_active': self.monitoring_active,
                'alert_handlers_count': len(self.alert_handlers),
                'queued_alerts': len(self.alert_queue)
            }
        }
