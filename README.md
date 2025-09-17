# 🔒 HiveLLM Secure Script Execution Environment

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![BIP-04](https://img.shields.io/badge/BIP--04-In%20Review-orange.svg)](https://github.com/hivellm/hive-gov/tree/main/bips/BIP-04)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org/)
[![Security](https://img.shields.io/badge/Security-Sandboxed-green.svg)](#security-features)

> **BIP-04 Implementation** - Secure script execution environment with comprehensive security controls

## 📋 Overview

Secure Script Execution Environment that provides sandboxed execution of Python scripts with:

- **🔒 Process Isolation**: Scripts run in isolated subprocesses
- **⚡ Resource Limits**: CPU, memory, and disk I/O controls
- **📊 Security Monitoring**: Real-time security event tracking
- **📝 Audit Logging**: Comprehensive execution audit trails
- **🛡️ Policy Management**: Configurable security policies

## Architecture

### Core Components

1. **SecureScriptExecutor**: Main class that handles script execution in a secure environment
2. **SecurityPolicy**: Manages security configuration and policy enforcement
3. **AuditLogger**: Provides comprehensive logging and audit trails
4. **Custom Exceptions**: Security-specific exception handling

### Security Layers

#### 1. Process Isolation
- Scripts run in isolated subprocesses
- No interference with main application or other scripts
- Automatic cleanup on completion

#### 2. Resource Management
- **CPU Time Limits**: Prevents infinite loops and excessive computation
- **Memory Limits**: Controls memory allocation to prevent exhaustion
- **File Size Limits**: Restricts file creation size
- **Process Limits**: Limits number of child processes

#### 3. Environment Security
- Clean environment variables (removes dangerous PATH components)
- Restricted module imports
- Quarantined working directory
- Minimal system access

#### 4. Audit & Monitoring
- Comprehensive execution logging
- Security event tracking
- Resource usage monitoring
- Alert generation for policy violations

## Usage

### Basic Usage

```python
from secure import SecureScriptExecutor

# Initialize executor
executor = SecureScriptExecutor()

# Execute a script
result = executor.execute_script("path/to/script.py")
print(f"Success: {result['success']}")
print(f"Output: {result['stdout']}")
```

### Advanced Usage

```python
from secure import SecureScriptExecutor

executor = SecureScriptExecutor()

# Execute with arguments and timeout
result = executor.execute_script(
    "path/to/script.py",
    args=["arg1", "arg2"],
    timeout=60.0  # 60 seconds
)

# Check execution details
print(f"Execution time: {result['execution_time']:.2f}s")
print(f"Return code: {result['return_code']}")
```

### Validation

```python
# Validate script before execution
if executor.validate_script("path/to/script.py"):
    result = executor.execute_script("path/to/script.py")
else:
    print("Script validation failed!")
```

## Configuration

### Security Policy File

The security policy is defined in `scripts/config/security_policy.yml`:

```yaml
security:
  execution:
    timeout_seconds: 300    # Maximum execution time
    cpu_seconds: 60         # CPU time limit
    memory_mb: 512          # Memory limit in MB
    file_size_mb: 100       # File size limit in MB
    max_processes: 5        # Maximum child processes

  filesystem:
    allowed_paths:          # Whitelisted paths
      - "/tmp"
      - "./data"
    blocked_operations:     # Blocked file operations
      - "delete"
      - "chmod"

  network:
    allowed_domains: []     # Empty = no network access
    blocked_ports: [22, 23] # Blocked network ports

  monitoring:
    log_level: "INFO"
    alert_thresholds:
      cpu_usage: 80         # Alert if CPU > 80%
      memory_usage: 90      # Alert if memory > 90%
```

## Security Features

### Threat Mitigation

1. **Code Injection Prevention**
   - Input sanitization
   - Restricted execution environment
   - Safe module importing

2. **Resource Exhaustion Prevention**
   - Hard resource limits
   - Process isolation
   - Automatic cleanup

3. **Privilege Separation**
   - Scripts run with minimal privileges
   - No access to sensitive system resources
   - Restricted filesystem access

4. **Audit Trail**
   - Complete execution records
   - Security event logging
   - Tamper-evident logs

### Monitoring & Alerts

- **Real-time Monitoring**: Execution tracking and resource usage
- **Security Alerts**: Immediate notification of policy violations
- **Performance Metrics**: Resource consumption statistics
- **Compliance Logging**: Audit trails for regulatory compliance

## Integration

### Existing Scripts

To integrate existing scripts with the secure environment:

1. **Import the executor**:
   ```python
   from secure import SecureScriptExecutor
   ```

2. **Replace direct execution**:
   ```python
   # Instead of: subprocess.run(["python", "script.py"])
   executor = SecureScriptExecutor()
   result = executor.execute_script("script.py")
   ```

3. **Handle results appropriately**:
   ```python
   if result['success']:
       # Process successful execution
       process_output(result['stdout'])
   else:
       # Handle execution failure
       log_error(result['stderr'])
   ```

### CI/CD Integration

The secure executor can be integrated into CI/CD pipelines:

```bash
# In CI/CD script
python -c "
from secure import SecureScriptExecutor
executor = SecureScriptExecutor()
result = executor.execute_script('test_script.py')
exit(0 if result['success'] else 1)
"
```

## Testing

### Running Tests

```bash
# Run all tests
cd scripts/secure
python tests/run_tests.py

# Run specific test module
python -m unittest tests.test_policy

# Run with coverage
python -c "import coverage; coverage.main()" -- tests/
```

### Writing Tests

```python
import unittest
from secure import SecureScriptExecutor

class TestMyScript(unittest.TestCase):
    def setUp(self):
        self.executor = SecureScriptExecutor()

    def test_script_execution(self):
        result = self.executor.execute_script("my_script.py")
        self.assertTrue(result['success'])
        self.assertIn("expected output", result['stdout'])
```

## Audit Logs

### Log Locations

- **Execution Audit**: `scripts/logs/execution_audit.log`
- **Security Events**: `scripts/logs/security_events.log`

### Log Format

Execution logs contain:
- Timestamp
- Script path and hash
- Arguments
- Return code
- Execution time
- Resource usage
- Success status

Security logs contain:
- Timestamp
- Event type
- Message
- Script path (if applicable)
- Additional details

## Performance Considerations

### Overhead

The secure execution environment adds minimal overhead:
- **CPU**: <5% for typical scripts
- **Memory**: ~10MB additional per execution
- **Startup Time**: ~50ms additional

### Optimization

- **Resource Pooling**: Reuse executor instances
- **Lazy Loading**: Load security modules on demand
- **Caching**: Cache policy validation results

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check file permissions
   - Verify script is in allowed path
   - Ensure quarantine directory exists

2. **Resource Limit Exceeded**
   - Increase limits in security policy
   - Optimize script resource usage
   - Check for memory leaks

3. **Timeout Errors**
   - Increase timeout in policy
   - Optimize script performance
   - Check for infinite loops

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

- **AST Analysis**: Static analysis of script code
- **Container Isolation**: Docker-based execution
- **Network Sandboxing**: Advanced network controls
- **Machine Learning**: Anomaly detection improvements
- **Performance Profiling**: Detailed execution profiling

## 🔗 Part of HiveLLM Ecosystem

This secure execution environment is part of the [HiveLLM ecosystem](../hivellm) - see main repository for complete system overview.

---

**BIP Implementation**: BIP-04 - Secure Script Execution Environment  
**Status**: ✅ Migrated and Functional  
**Repository**: HiveLLM Security Environment

This will create a sample script and demonstrate the secure execution environment capabilities.
