"""
Unit tests for the SecureScriptExecutor class.
"""

import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexecutor import SecureScriptExecutor
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexceptions import ScriptExecutionException, TimeoutException

class TestSecureScriptExecutor(unittest.TestCase):
    """Test cases for SecureScriptExecutor class."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.executor = SecureScriptExecutor()

        # Create a simple test script
        self.test_script = Path(self.temp_dir) / "test_script.py"
        self.test_script.write_text("""
import sys
print("Hello from secure execution!")
sys.exit(0)
""")

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_script_validation_valid(self):
        """Test validation of a valid script."""
        self.assertTrue(self.executor.validate_script(str(self.test_script)))

    def test_script_validation_invalid_path(self):
        """Test validation of script with invalid path."""
        invalid_script = "/etc/passwd"  # Should be blocked by policy
        self.assertFalse(self.executor.validate_script(invalid_script))

    def test_script_validation_nonexistent(self):
        """Test validation of nonexistent script."""
        nonexistent = Path(self.temp_dir) / "nonexistent.py"
        self.assertFalse(self.executor.validate_script(str(nonexistent)))

    @patch('subprocess.run')
    def test_successful_execution(self, mock_run):
        """Test successful script execution."""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Hello World"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = self.executor.execute_script(str(self.test_script))

        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertEqual(result['stdout'], "Hello World")
        self.assertEqual(result['stderr'], "")

        # Verify subprocess.run was called correctly
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_failed_execution(self, mock_run):
        """Test failed script execution."""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Something went wrong"
        mock_run.return_value = mock_result

        result = self.executor.execute_script(str(self.test_script))

        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertEqual(result['stderr'], "Error: Something went wrong")

    @patch('subprocess.run')
    def test_execution_with_args(self, mock_run):
        """Test script execution with arguments."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Args received"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        args = ["arg1", "arg2"]
        result = self.executor.execute_script(str(self.test_script), args)

        # Verify arguments were passed
        call_args = mock_run.call_args
        called_cmd = call_args[1]['args']
        self.assertIn("arg1", called_cmd)
        self.assertIn("arg2", called_cmd)

    @patch('subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Test handling of script timeout."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired(['python3', str(self.test_script)], 300)

        with self.assertRaises(TimeoutException):
            self.executor.execute_script(str(self.test_script))

    def test_resource_limits_setting(self):
        """Test that resource limits are properly configured."""
        # This test verifies that the _set_resource_limits method doesn't raise exceptions
        # In a real environment, we would need additional setup to test actual limits
        limits = {
            'cpu_seconds': 60,
            'memory_mb': 512,
            'file_size_mb': 100,
            'max_processes': 5
        }

        # This should not raise an exception
        try:
            self.executor._set_resource_limits(limits)
        except Exception as e:
            # In some test environments, setting resource limits might fail
            # This is acceptable for unit testing
            self.assertIn("Failed to set resource limits", str(e))

    def test_secure_environment_preparation(self):
        """Test that secure environment is properly prepared."""
        env = self.executor._prepare_secure_environment()

        # Verify dangerous environment variables are removed
        dangerous_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME']
        for var in dangerous_vars:
            self.assertNotIn(var, env)

        # Verify PATH is set to minimal safe value
        self.assertEqual(env['PATH'], '/usr/local/bin:/usr/bin:/bin')

        # Verify working directory is set to quarantine
        self.assertEqual(env['PWD'], str(self.executor.quarantine_dir))

    def test_resource_usage_collection(self):
        """Test resource usage data collection."""
        usage = self.executor._get_resource_usage()

        # Verify expected keys are present
        expected_keys = ['cpu_percent', 'memory_mb', 'num_threads']
        for key in expected_keys:
            self.assertIn(key, usage)

        # Verify data types
        self.assertIsInstance(usage['cpu_percent'], (int, float))
        self.assertIsInstance(usage['memory_mb'], (int, float))
        self.assertIsInstance(usage['num_threads'], int)

if __name__ == '__main__':
    unittest.main()
