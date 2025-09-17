"""
Unit tests for the SecurityPolicy class.
"""

import unittest
import tempfile
import yaml
from pathlib import Path
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); frompolicy import SecurityPolicy
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexceptions import PolicyViolationException

class TestSecurityPolicy(unittest.TestCase):
    """Test cases for SecurityPolicy class."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.policy_file = Path(self.temp_dir) / "test_policy.yml"

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def create_valid_policy(self):
        """Create a valid policy file for testing."""
        policy_data = {
            'security': {
                'execution': {
                    'timeout_seconds': 300,
                    'cpu_seconds': 60,
                    'memory_mb': 512,
                    'file_size_mb': 100,
                    'max_processes': 5
                },
                'filesystem': {
                    'allowed_paths': ['/tmp', './data'],
                    'blocked_operations': ['delete', 'chmod']
                },
                'network': {
                    'allowed_domains': [],
                    'blocked_ports': [22, 23]
                },
                'monitoring': {
                    'log_level': 'INFO',
                    'alert_thresholds': {
                        'cpu_usage': 80,
                        'memory_usage': 90
                    }
                }
            }
        }

        with open(self.policy_file, 'w') as f:
            yaml.dump(policy_data, f)

    def test_valid_policy_loading(self):
        """Test loading a valid policy file."""
        self.create_valid_policy()
        policy = SecurityPolicy(str(self.policy_file))

        # Test execution limits
        limits = policy.get_execution_limits()
        self.assertEqual(limits['timeout_seconds'], 300)
        self.assertEqual(limits['cpu_seconds'], 60)

        # Test filesystem policy
        fs_policy = policy.get_filesystem_policy()
        self.assertIn('/tmp', fs_policy['allowed_paths'])
        self.assertIn('delete', fs_policy['blocked_operations'])

    def test_missing_policy_file(self):
        """Test handling of missing policy file."""
        with self.assertRaises(PolicyViolationException):
            SecurityPolicy("nonexistent_file.yml")

    def test_invalid_policy_structure(self):
        """Test handling of invalid policy structure."""
        # Create policy without required sections
        invalid_policy = {'incomplete': 'policy'}
        with open(self.policy_file, 'w') as f:
            yaml.dump(invalid_policy, f)

        with self.assertRaises(PolicyViolationException):
            SecurityPolicy(str(self.policy_file))

    def test_path_validation(self):
        """Test filesystem path validation."""
        self.create_valid_policy()
        policy = SecurityPolicy(str(self.policy_file))

        # Test allowed paths
        self.assertTrue(policy.is_path_allowed('/tmp/test.txt'))
        self.assertTrue(policy.is_path_allowed('./data/file.py'))

        # Test disallowed paths
        self.assertFalse(policy.is_path_allowed('/etc/passwd'))
        self.assertFalse(policy.is_path_allowed('/root/secret'))

    def test_operation_validation(self):
        """Test filesystem operation validation."""
        self.create_valid_policy()
        policy = SecurityPolicy(str(self.policy_file))

        # Test blocked operations
        self.assertTrue(policy.is_operation_blocked('delete'))
        self.assertTrue(policy.is_operation_blocked('chmod'))

        # Test allowed operations
        self.assertFalse(policy.is_operation_blocked('read'))
        self.assertFalse(policy.is_operation_blocked('write'))

    def test_network_validation(self):
        """Test network access validation."""
        self.create_valid_policy()
        policy = SecurityPolicy(str(self.policy_file))

        # Test blocked ports
        self.assertTrue(policy.is_port_blocked(22))
        self.assertTrue(policy.is_port_blocked(23))

        # Test allowed ports
        self.assertFalse(policy.is_port_blocked(80))
        self.assertFalse(policy.is_port_blocked(443))

    def test_alert_thresholds(self):
        """Test alert threshold validation."""
        self.create_valid_policy()
        policy = SecurityPolicy(str(self.policy_file))

        # Test threshold alerts
        self.assertTrue(policy.should_alert('cpu_usage', 85))
        self.assertFalse(policy.should_alert('cpu_usage', 75))

        self.assertTrue(policy.should_alert('memory_usage', 95))
        self.assertFalse(policy.should_alert('memory_usage', 85))

if __name__ == '__main__':
    unittest.main()
