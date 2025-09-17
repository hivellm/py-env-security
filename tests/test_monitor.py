"""
Unit tests for the SecurityMonitor class.
"""

import unittest
from unittest.mock import MagicMock
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); frommonitor import SecurityMonitor
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); frompolicy import SecurityPolicy
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromaudit import AuditLogger

class TestSecurityMonitor(unittest.TestCase):
    """Test cases for SecurityMonitor class."""

    def setUp(self):
        """Set up test environment."""
        self.policy = SecurityPolicy()
        self.audit_logger = AuditLogger()
        self.monitor = SecurityMonitor(self.policy, self.audit_logger)

    def tearDown(self):
        """Clean up test environment."""
        self.monitor.stop_monitoring()

    def test_initialization(self):
        """Test monitor initialization."""
        stats = self.monitor.get_stats()
        self.assertEqual(stats['total_executions'], 0)
        self.assertEqual(stats['successful_executions'], 0)
        self.assertEqual(stats['failed_executions'], 0)
        self.assertEqual(stats['security_violations'], 0)
        self.assertEqual(stats['alerts_sent'], 0)

    def test_execution_recording(self):
        """Test execution recording."""
        # Record successful execution
        self.monitor.record_execution(
            "/test/script.py", True, 1.5,
            {'cpu_percent': 45.0, 'memory_mb': 100.0}
        )

        stats = self.monitor.get_stats()
        self.assertEqual(stats['total_executions'], 1)
        self.assertEqual(stats['successful_executions'], 1)
        self.assertEqual(stats['failed_executions'], 0)

        # Record failed execution
        self.monitor.record_execution(
            "/test/script2.py", False, 2.0,
            {'cpu_percent': 60.0, 'memory_mb': 150.0}
        )

        stats = self.monitor.get_stats()
        self.assertEqual(stats['total_executions'], 2)
        self.assertEqual(stats['successful_executions'], 1)
        self.assertEqual(stats['failed_executions'], 1)

    def test_alert_handlers(self):
        """Test alert handler functionality."""
        alerts_received = []

        def test_handler(alert_type, alert_data):
            alerts_received.append((alert_type, alert_data))

        # Add handler
        self.monitor.add_alert_handler(test_handler)

        # Record execution that should trigger alert
        self.monitor.record_execution(
            "/test/script.py", True, 300.0,  # Long execution time
            {'cpu_percent': 90.0, 'memory_mb': 200.0}
        )

        # Start monitoring to process alerts
        self.monitor.start_monitoring()
        import time
        time.sleep(0.1)  # Allow time for alert processing

        # Check that alerts were sent
        self.assertGreater(len(alerts_received), 0)

        # Remove handler
        self.monitor.remove_alert_handler(test_handler)

    def test_security_event_recording(self):
        """Test security event recording."""
        self.monitor.record_security_event(
            "TEST_EVENT",
            "Test security event",
            "/test/script.py",
            {"test": "data"}
        )

        stats = self.monitor.get_stats()
        self.assertEqual(stats['security_violations'], 1)

    def test_recent_alerts(self):
        """Test recent alerts retrieval."""
        # Initially should be empty
        alerts = self.monitor.get_recent_alerts()
        self.assertEqual(len(alerts), 0)

        # Add some alerts by recording executions
        self.monitor.record_execution("/test/script.py", True, 300.0, {})
        self.monitor.record_execution("/test/script.py", True, 1.0, {'cpu_percent': 95.0})

        # Should have some alerts now
        alerts = self.monitor.get_recent_alerts(10)
        self.assertGreater(len(alerts), 0)

    def test_generate_report(self):
        """Test report generation."""
        # Record some activity
        self.monitor.record_execution("/test/script.py", True, 1.0, {})
        self.monitor.record_security_event("TEST", "Test event")

        report = self.monitor.generate_report()

        # Check report structure
        self.assertIn('timestamp', report)
        self.assertIn('stats', report)
        self.assertIn('recent_alerts', report)
        self.assertIn('system_health', report)

        # Check stats in report
        self.assertEqual(report['stats']['total_executions'], 1)
        self.assertEqual(report['stats']['security_violations'], 1)

if __name__ == '__main__':
    unittest.main()
