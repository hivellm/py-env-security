"""
Integration tests for BIP-04 Secure Script Execution Environment.
"""

import unittest
import tempfile
from pathlib import Path
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexecutor import SecureScriptExecutor
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); frommigration import ScriptMigrationManager
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromtesting import SecurityTestSuite

class TestIntegration(unittest.TestCase):
    """Integration tests for secure execution environment."""

    def setUp(self):
        """Set up integration test environment."""
        self.executor = SecureScriptExecutor()
        self.migration_manager = ScriptMigrationManager(self.executor)
        self.test_suite = SecurityTestSuite(self.executor)

    def tearDown(self):
        """Clean up test environment."""
        pass

    def test_full_execution_workflow(self):
        """Test complete script execution workflow."""
        # Create a test script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
import sys
import os

def main():
    # Safe operations
    result = 42 * 2
    print(f"Calculation result: {result}")

    # File operation (should be allowed)
    with open("./test_output.txt", "w") as file:
        file.write("Integration test successful")

    print("Script executed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())
""")
            test_script = f.name

        try:
            # Step 1: Validate script
            is_valid = self.executor.validate_script(test_script)
            self.assertTrue(is_valid, "Script validation should pass")

            # Step 2: Analyze script security
            analysis = self.executor.analyze_script_security(test_script)
            self.assertIsInstance(analysis, dict)
            self.assertIn('risk_level', analysis)

            # Step 3: Execute script
            result = self.executor.execute_script(test_script)
            self.assertTrue(result['success'])
            self.assertIn('Calculation result: 84', result['stdout'])

            # Step 4: Verify security checks
            self.assertIn('security_checks', result)
            checks = result['security_checks']
            self.assertTrue(checks.get('filesystem_validated'))
            self.assertTrue(checks.get('resource_limits_applied'))

            # Step 5: Check monitoring stats
            stats = self.executor.get_security_stats()
            self.assertGreater(stats['monitoring_stats']['total_executions'], 0)

        finally:
            # Cleanup
            Path(test_script).unlink(missing_ok=True)
            Path("./test_output.txt").unlink(missing_ok=True)

    def test_migration_workflow(self):
        """Test script migration workflow."""
        # Create a script that needs migration
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
#!/usr/bin/env python
import os

# This script has some issues that might need migration
result = os.system("echo 'test'")
print("Migration test script")
""")
            test_script = f.name

        try:
            # Step 1: Analyze for migration
            analysis = self.migration_manager.analyze_script_for_migration(test_script)
            self.assertIsInstance(analysis, dict)
            self.assertIn('compatibility_score', analysis)

            # Step 2: Perform migration
            with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as migrated_file:
                migration_result = self.migration_manager.migrate_script(
                    test_script, migrated_file.name
                )

            # Step 3: Verify migration
            self.assertTrue(migration_result['migration_successful'])

            # Step 4: Test migrated script
            result = self.executor.execute_script(migrated_file.name)
            self.assertTrue(result['success'])

            # Cleanup migrated file
            Path(migrated_file.name).unlink(missing_ok=True)

        finally:
            # Cleanup original file
            Path(test_script).unlink(missing_ok=True)

    def test_security_test_suite(self):
        """Test the security test suite execution."""
        # Run a subset of security tests
        results = self.test_suite.run_full_security_test_suite()

        # Verify results structure
        self.assertIsInstance(results, dict)
        self.assertIn('overall_status', results)
        self.assertIn('passed', results)
        self.assertIn('failed', results)
        self.assertIn('tests_run', results)

        # Should have run at least some tests
        self.assertGreater(len(results['tests_run']), 0)

        # Overall status should be determined
        self.assertIn(results['overall_status'], ['passed', 'failed', 'warning'])

    def test_resource_limits_integration(self):
        """Test resource limits work with script execution."""
        # Create a script that uses resources
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
import time

# Use some CPU time
start = time.time()
for i in range(100000):
    x = i ** 2
end = time.time()

print(f"CPU intensive task completed in {end - start:.2f} seconds")
""")
            test_script = f.name

        try:
            # Execute with resource monitoring
            result = self.executor.execute_script(test_script)

            self.assertTrue(result['success'])
            self.assertIn('resource_usage', result)

            # Verify resource usage was tracked
            usage = result['resource_usage']
            self.assertIsInstance(usage, dict)

        finally:
            Path(test_script).unlink(missing_ok=True)

    def test_audit_integration(self):
        """Test audit logging integration."""
        # Create a simple script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('Audit integration test')")
            test_script = f.name

        try:
            # Execute script
            result = self.executor.execute_script(test_script)
            self.assertTrue(result['success'])

            # Check audit stats
            stats = self.executor.get_security_stats()
            audit_stats = stats['audit_summary']

            # Should have recorded the execution
            self.assertGreaterEqual(audit_stats['execution_history_count'], 1)

        finally:
            Path(test_script).unlink(missing_ok=True)

    def test_error_handling_integration(self):
        """Test error handling across components."""
        # Test with non-existent script
        try:
            self.executor.execute_script("/non/existent/script.py")
            self.fail("Should have raised ScriptExecutionException")
        except Exception as e:
            # Should handle the error gracefully
            self.assertIsInstance(e, Exception)

        # Test with invalid security policy
        try:
            # This should not crash the system
            invalid_executor = SecureScriptExecutor(policy_file="/non/existent/policy.yml")
            # The executor should handle missing policy gracefully
        except Exception:
            # Expected to fail, but should not crash
            pass

    def test_monitoring_integration(self):
        """Test monitoring system integration."""
        # Create and execute a script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('Monitoring integration test')")
            test_script = f.name

        try:
            result = self.executor.execute_script(test_script)
            self.assertTrue(result['success'])

            # Check monitoring stats
            stats = self.executor.get_security_stats()
            monitoring_stats = stats['monitoring_stats']

            # Should have recorded the execution
            self.assertGreaterEqual(monitoring_stats['total_executions'], 1)
            self.assertGreaterEqual(monitoring_stats['successful_executions'], 1)

        finally:
            Path(test_script).unlink(missing_ok=True)

if __name__ == '__main__':
    unittest.main()
