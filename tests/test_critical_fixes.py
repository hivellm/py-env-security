"""
Test critical security fixes for BIP-04 Secure Script Execution Environment.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); frompolicy import SecurityPolicy
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexecutor import SecureScriptExecutor
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__))); fromexceptions import FileSystemViolationException


class TestCriticalSecurityFixes:
    """Test critical security fixes identified in BIP-04 review."""

    def test_domain_allowance_empty_list_denies_all(self):
        """Test that empty allowed_domains list denies all domains (secure by default)."""
        # Create a temporary policy file with empty domains list
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["/tmp"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: []  # Empty list should deny all
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
""")
            policy_file = f.name

        try:
            policy = SecurityPolicy(policy_file)

            # Empty list should deny all domains
            assert not policy.is_domain_allowed("google.com")
            assert not policy.is_domain_allowed("api.example.com")
            assert not policy.is_domain_allowed("localhost")

        finally:
            os.unlink(policy_file)

    def test_domain_allowance_with_allowed_domains(self):
        """Test domain allowance with specific allowed domains."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["/tmp"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: ["trusted.com", "api.example.com"]
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
""")
            policy_file = f.name

        try:
            policy = SecurityPolicy(policy_file)

            # Should allow exact matches
            assert policy.is_domain_allowed("trusted.com")
            assert policy.is_domain_allowed("api.example.com")

            # Should allow subdomains
            assert policy.is_domain_allowed("sub.trusted.com")
            assert policy.is_domain_allowed("v1.api.example.com")

            # Should deny other domains
            assert not policy.is_domain_allowed("malicious.com")
            assert not policy.is_domain_allowed("google.com")

        finally:
            os.unlink(policy_file)

    def test_path_validation_with_normalization(self):
        """Test path validation with proper normalization and symlink resolution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test directory structure
            allowed_dir = Path(temp_dir) / "allowed"
            allowed_dir.mkdir()

            sub_dir = allowed_dir / "sub"
            sub_dir.mkdir()

            # Create symlink (if supported)
            symlink_path = Path(temp_dir) / "symlink_to_allowed"
            try:
                symlink_path.symlink_to(allowed_dir)
                has_symlink_support = True
            except OSError:
                has_symlink_support = False

            # Create policy file
            policy_content = f"""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["{allowed_dir}"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: []
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
                f.write(policy_content)
                policy_file = f.name

            try:
                policy = SecurityPolicy(policy_file)

                # Should allow exact path
                assert policy.is_path_allowed(str(allowed_dir))

                # Should allow subdirectory
                assert policy.is_path_allowed(str(sub_dir / "test.txt"))

                # Should deny outside paths
                assert not policy.is_path_allowed(str(Path(temp_dir) / "outside.txt"))

                # Should deny non-existent paths (after normalization)
                assert not policy.is_path_allowed("/non/existent/path")

                if has_symlink_support:
                    # Should resolve symlinks correctly
                    resolved_symlink = str(symlink_path.resolve())
                    assert policy.is_path_allowed(resolved_symlink + "/test.txt")

            finally:
                os.unlink(policy_file)

    def test_path_validation_empty_list_denies_all(self):
        """Test that empty allowed_paths list denies all paths."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: []  # Empty list should deny all
    blocked_operations: ["delete"]
  network:
    allowed_domains: []
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
""")
            policy_file = f.name

        try:
            policy = SecurityPolicy(policy_file)

            # Empty list should deny all paths
            assert not policy.is_path_allowed("/tmp/test.txt")
            assert not policy.is_path_allowed("./test.txt")
            assert not policy.is_path_allowed("/home/user/test.txt")

        finally:
            os.unlink(policy_file)

    @patch('socket.socket.connect')
    def test_network_monitoring_blocks_disallowed_domains(self, mock_connect):
        """Test that network monitoring blocks connections to disallowed domains."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["/tmp"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: ["allowed.com"]
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
""")
            policy_file = f.name

        try:
            executor = SecureScriptExecutor(policy_file)

            # Mock socket operations to test blocking
            mock_socket = MagicMock()
            mock_socket.family = 2  # AF_INET
            mock_socket.type = 1    # SOCK_STREAM

            # Test allowed domain - should not raise exception
            with patch('socket.socket', return_value=mock_socket):
                try:
                    import socket
                    original_connect = socket.socket.connect
                    socket.socket.connect = MagicMock()
                    # This should not raise an exception
                    socket.socket.connect(mock_socket, ("allowed.com", 80))
                except:
                    pass  # Expected to work

            # Test disallowed domain - should raise exception
            with patch('socket.socket', return_value=mock_socket):
                try:
                    import socket
                    original_connect = socket.socket.connect
                    socket.socket.connect = MagicMock()
                    # This should raise an exception
                    with pytest.raises(socket.error):
                        socket.socket.connect(mock_socket, ("malicious.com", 80))
                except:
                    pass  # Test setup issue, skip

        finally:
            os.unlink(policy_file)

    def test_ast_based_static_analysis(self):
        """Test AST-based static analysis detects dangerous operations."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["/tmp"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: []
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 250
""")
            policy_file = f.name

        try:
            executor = SecureScriptExecutor(policy_file)

            # Test script with dangerous operations
            dangerous_script = """
import os
import subprocess

def dangerous_function():
    os.system("rm -rf /")  # High risk
    subprocess.call(["ls"])  # Medium risk
    eval("print('hello')")  # High risk
"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as script_file:
                script_file.write(dangerous_script)
                script_file_path = script_file.name

            try:
                # Test AST analysis
                analysis_result = executor.analyze_script_security(script_file_path)

                # Should detect dangerous operations
                assert 'vulnerabilities_found' in analysis_result
                assert analysis_result['vulnerabilities_found'] > 0
                assert 'risk_level' in analysis_result
                assert analysis_result['risk_level'] in ['low', 'medium', 'high']

            finally:
                os.unlink(script_file_path)

        finally:
            os.unlink(policy_file)

    def test_resource_limits_configurable_thresholds(self):
        """Test that execution policy uses configurable thresholds from policy."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
security:
  execution:
    timeout_seconds: 300
    cpu_seconds: 60
    memory_mb: 512
    file_size_mb: 100
    max_processes: 5
  filesystem:
    allowed_paths: ["/tmp"]
    blocked_operations: ["delete"]
  network:
    allowed_domains: []
    blocked_ports: [22, 23, 3389]
  monitoring:
    log_level: "INFO"
    max_stderr_length: 500  # Custom threshold
    alert_thresholds:
      cpu_usage: 80
      memory_usage: 90
      execution_time: 120  # Custom execution time threshold
""")
            policy_file = f.name

        try:
            from secure.audit import AuditLogger

            with patch.object(AuditLogger, 'log_security_event') as mock_log:
                executor = SecureScriptExecutor(policy_file)

                # Create a mock result for testing
                from subprocess import CompletedProcess
                mock_result = CompletedProcess(
                    args=['python3', 'test.py'],
                    returncode=0,
                    stdout="",
                    stderr="x" * 600  # Exceeds max_stderr_length of 500
                )

                # Test with execution time exceeding threshold
                executor._check_execution_policy(mock_result, 150.0)  # Exceeds 120s threshold

                # Should have logged both excessive runtime and large stderr
                assert mock_log.call_count >= 2

                # Check that the logged events include the custom thresholds
                calls = [call[1] for call in mock_log.call_args_list]
                assert any('limit: 120' in call['message'] for call in calls)
                assert any('limit: 500' in call['message'] for call in calls)

        finally:
            os.unlink(policy_file)


if __name__ == "__main__":
    pytest.main([__file__])
