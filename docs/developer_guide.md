# BIP-04 Developer Guide

## Overview

This guide provides comprehensive information for developers working with the BIP-04 Secure Script Execution Environment.

## Architecture

### Core Components

#### SecureScriptExecutor
The main entry point for secure script execution:

```python
from secure import SecureScriptExecutor

executor = SecureScriptExecutor()
result = executor.execute_script("my_script.py")
```

#### Security Components
- **SecurityPolicy**: Manages security rules and configuration
- **AuditLogger**: Handles comprehensive logging and audit trails
- **SecurityMonitor**: Real-time monitoring and alerting
- **SecurityAnalyzer**: Static analysis for vulnerability detection

## Usage Examples

### Basic Script Execution

```python
from secure import SecureScriptExecutor

# Initialize executor
executor = SecureScriptExecutor()

# Execute a script
result = executor.execute_script("path/to/script.py")

# Check results
if result['success']:
    print("Script executed successfully")
    print("Output:", result['stdout'])
else:
    print("Script execution failed")
    print("Error:", result['stderr'])
```

### Advanced Execution with Monitoring

```python
# Execute with custom timeout and arguments
result = executor.execute_script(
    "script.py",
    args=["--input", "data.txt", "--output", "result.txt"],
    timeout=30.0
)

# Access detailed execution information
print(f"Execution time: {result['execution_time']:.2f}s")
print(f"Security checks passed: {result['security_checks']}")

if 'static_analysis' in result:
    analysis = result['static_analysis']
    print(f"Vulnerabilities found: {analysis['vulnerabilities_found']}")
```

### Security Analysis

```python
# Analyze script without execution
analysis = executor.analyze_script_security("script.py")

print(f"Risk Level: {analysis['risk_level']}")
print(f"Vulnerabilities: {analysis['vulnerabilities_found']}")

for vuln in analysis['vulnerabilities']:
    print(f"- {vuln['type']}: {vuln['description']}")
    print(f"  Line {vuln['line']}: {vuln['code']}")
```

### Monitoring and Statistics

```python
# Get security monitoring statistics
stats = executor.get_security_stats()

print("Monitoring Stats:")
print(f"  Total executions: {stats['monitoring_stats']['total_executions']}")
print(f"  Security violations: {stats['monitoring_stats']['security_violations']}")

print("Recent Alerts:")
for alert in stats['recent_alerts'][:3]:
    print(f"  - {alert['type']}: {alert['message']}")
```

## Security Best Practices

### Writing Secure Scripts

#### 1. Input Validation
```python
import sys

# Always validate inputs
if len(sys.argv) < 2:
    print("Usage: script.py <input_file>")
    sys.exit(1)

input_file = sys.argv[1]
# Validate file exists and is readable
if not os.path.isfile(input_file):
    print(f"Error: {input_file} not found")
    sys.exit(1)
```

#### 2. Safe File Operations
```python
# Use secure file operations
import os
from pathlib import Path

def safe_read_file(file_path):
    path = Path(file_path)

    # Validate path is within allowed directory
    allowed_dir = Path("./data")
    if not path.resolve().is_relative_to(allowed_dir.resolve()):
        raise ValueError("Access denied: file outside allowed directory")

    with open(path, 'r') as f:
        return f.read()
```

#### 3. Avoid Dangerous Operations
```python
# ❌ DON'T do this
import os
os.system("rm -rf /")  # Dangerous!

# ✅ DO this instead
import shutil
shutil.rmtree("./temp")  # Safer, controlled operation
```

### Common Security Issues

#### Command Injection
```python
# ❌ Vulnerable
filename = input("Enter filename: ")
os.system(f"ls {filename}")

# ✅ Secure
import subprocess
filename = input("Enter filename: ")
# Validate filename
if not filename.replace(".", "").replace("/", "").isalnum():
    raise ValueError("Invalid filename")

result = subprocess.run(["ls", filename], capture_output=True, text=True)
```

#### Path Traversal
```python
# ❌ Vulnerable
filename = "../../../etc/passwd"
with open(filename, 'r') as f:
    content = f.read()

# ✅ Secure
from pathlib import Path

filename = "../../../etc/passwd"
path = Path("./data") / filename

# Resolve to absolute path and check
abs_path = path.resolve()
allowed_path = Path("./data").resolve()

if not abs_path.is_relative_to(allowed_path):
    raise ValueError("Access denied")

with open(abs_path, 'r') as f:
    content = f.read()
```

## Configuration

### Security Policy Configuration

The security policy is defined in `scripts/config/security_policy.yml`:

```yaml
security:
  execution:
    timeout_seconds: 300      # Maximum execution time
    cpu_seconds: 60           # CPU time limit
    memory_mb: 512            # Memory limit
    file_size_mb: 100         # File size limit
    max_processes: 5          # Maximum child processes

  filesystem:
    allowed_paths:            # Whitelisted directories
      - "/tmp"
      - "./data"
      - "./logs"
    blocked_operations:       # Blocked file operations
      - "delete"
      - "chmod"
      - "chown"

  network:
    allowed_domains: []       # Empty = no network access
    blocked_ports: [22, 23, 3389]  # Blocked ports

  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80           # Alert if CPU > 80%
      memory_usage: 90        # Alert if memory > 90%
      execution_time: 250     # Alert if execution > 250s
```

### Custom Configuration

```python
# Load custom security policy
executor = SecureScriptExecutor(policy_file="custom_policy.yml")

# Or modify policy programmatically
policy = executor.policy
policy._policy['execution']['timeout_seconds'] = 600  # Extend timeout
```

## Error Handling

### Handling Execution Errors

```python
from secure import ScriptExecutionException

try:
    result = executor.execute_script("script.py")
    if not result['success']:
        print("Script failed with return code:", result['return_code'])
        print("Error output:", result['stderr'])
except ScriptExecutionException as e:
    print(f"Execution failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Security Exceptions

```python
from secure import (
    ResourceLimitException,
    FileSystemViolationException,
    NetworkViolationException,
    PolicyViolationException,
    TimeoutException
)

try:
    result = executor.execute_script("script.py")
except ResourceLimitException:
    print("Script exceeded resource limits")
except FileSystemViolationException:
    print("Script attempted unauthorized file access")
except NetworkViolationException:
    print("Script attempted unauthorized network access")
except PolicyViolationException:
    print("Script violated security policy")
except TimeoutException:
    print("Script execution timed out")
```

## Testing

### Unit Testing

```python
import unittest
from secure import SecureScriptExecutor

class TestMyScript(unittest.TestCase):
    def setUp(self):
        self.executor = SecureScriptExecutor()

    def test_script_execution(self):
        result = self.executor.execute_script("test_script.py")
        self.assertTrue(result['success'])
        self.assertIn("expected output", result['stdout'])

    def test_security_validation(self):
        # Test that security checks work
        is_valid = self.executor.validate_script("safe_script.py")
        self.assertTrue(is_valid)

        is_valid = self.executor.validate_script("/etc/passwd")
        self.assertFalse(is_valid)
```

### Security Testing

```python
from secure.testing import SecurityTestSuite

# Run comprehensive security tests
test_suite = SecurityTestSuite(executor)
results = test_suite.run_full_security_test_suite()

print(f"Tests passed: {results['passed']}")
print(f"Tests failed: {results['failed']}")

for test_name, test_result in results['details'].items():
    print(f"{test_name}: {test_result['status']}")
```

## Migration Guide

### Migrating Existing Scripts

```python
from secure.migration import ScriptMigrationManager

migration_manager = ScriptMigrationManager(executor)

# Analyze script for migration requirements
analysis = migration_manager.analyze_script_for_migration("old_script.py")
print(f"Migration required: {analysis['migration_required']}")
print(f"Compatibility score: {analysis['compatibility_score']}%")

# Migrate script
if analysis['migration_required']:
    result = migration_manager.migrate_script("old_script.py")
    if result['migration_successful']:
        print("Migration completed successfully")
    else:
        print("Migration failed:", result.get('error'))
```

### Common Migration Patterns

1. **Replace direct execution**:
   ```python
   # Before
   subprocess.run(["python", "script.py"])

   # After
   result = executor.execute_script("script.py")
   ```

2. **Handle file paths**:
   ```python
   # Before
   with open("/absolute/path/file.txt", 'r') as f:

   # After
   with open("./data/file.txt", 'r') as f:  # Use relative paths
   ```

3. **Validate inputs**:
   ```python
   # Add input validation
   filename = sys.argv[1]
   if not filename.replace(".", "").replace("/", "").isalnum():
       raise ValueError("Invalid filename")
   ```

## Performance Optimization

### Profiling Execution

```python
import time

start_time = time.time()
result = executor.execute_script("script.py")
end_time = time.time()

print(f"Total time: {end_time - start_time:.2f}s")
print(f"Script time: {result['execution_time']:.2f}s")
print(f"Security overhead: {(end_time - start_time - result['execution_time']):.2f}s")
```

### Resource Usage Monitoring

```python
# Monitor resource usage during execution
result = executor.execute_script("script.py")

if 'resource_usage' in result:
    usage = result['resource_usage']
    print(f"CPU usage: {usage.get('cpu_percent', 'N/A')}%")
    print(f"Memory usage: {usage.get('memory_mb', 'N/A')} MB")
    print(f"Thread count: {usage.get('num_threads', 'N/A')}")
```

## Troubleshooting

### Common Issues

#### Import Errors
```python
# Check Python path
import sys
print("Python path:", sys.path)

# Add secure package to path
sys.path.insert(0, "/path/to/secure")
```

#### Permission Errors
```python
# Check file permissions
import os
print("File permissions:", oct(os.stat("script.py").st_mode))

# Check execution permissions
os.chmod("script.py", 0o755)
```

#### Configuration Errors
```python
# Validate configuration
import yaml
with open("scripts/config/security_policy.yml", 'r') as f:
    config = yaml.safe_load(f)
    print("Configuration loaded successfully")
```

### Debug Mode

Enable detailed logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Execute with debug logging
result = executor.execute_script("script.py")
```

## API Reference

### SecureScriptExecutor

#### Methods

- `execute_script(script_path, args=None, timeout=None)`: Execute script securely
- `validate_script(script_path)`: Validate script against security policy
- `analyze_script_security(script_path)`: Perform security analysis
- `get_security_stats()`: Get monitoring statistics

#### Properties

- `policy`: SecurityPolicy instance
- `audit_logger`: AuditLogger instance
- `security_monitor`: SecurityMonitor instance

### SecurityPolicy

#### Methods

- `get_execution_limits()`: Get execution resource limits
- `get_filesystem_policy()`: Get filesystem access policy
- `get_network_policy()`: Get network access policy
- `is_path_allowed(path)`: Check if path is allowed
- `is_operation_blocked(operation)`: Check if operation is blocked

### SecurityMonitor

#### Methods

- `record_execution(script_path, success, execution_time, resource_usage)`: Record execution
- `record_security_event(event_type, message, script_path=None, details=None)`: Record security event
- `get_stats()`: Get monitoring statistics
- `get_recent_alerts(limit=10)`: Get recent alerts

## Support

For additional help:
- Review the audit logs in `scripts/logs/`
- Check the security policy configuration
- Run the test suite: `python -m secure.tests.run_tests`
- Contact the development team with detailed error information
