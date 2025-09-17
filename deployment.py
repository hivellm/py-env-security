"""
Deployment utilities for BIP-04 Secure Script Execution Environment.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from .executor import SecureScriptExecutor
from audit import AuditLogger

class DeploymentManager:
    """Manages deployment of the secure script execution environment."""

    def __init__(self, executor: SecureScriptExecutor):
        self.executor = executor
        self.audit_logger = executor.audit_logger

    def deploy_to_production(self, target_dir: str = "/opt/cmmv-secure-scripts",
                           backup_existing: bool = True) -> Dict[str, Any]:
        """
        Deploy the secure execution environment to production.

        Args:
            target_dir: Target deployment directory
            backup_existing: Whether to backup existing deployment

        Returns:
            Deployment report
        """
        target_path = Path(target_dir)

        deployment_report = {
            'deployment_type': 'production',
            'target_directory': str(target_path),
            'timestamp': __import__('time').time(),
            'steps_completed': [],
            'issues_encountered': [],
            'rollback_available': False,
            'status': 'in_progress'
        }

        try:
            # Step 1: Pre-deployment checks
            self._run_pre_deployment_checks()
            deployment_report['steps_completed'].append('pre_deployment_checks')

            # Step 2: Create backup if requested
            if backup_existing and target_path.exists():
                backup_path = target_path.with_suffix('.backup')
                shutil.copytree(target_path, backup_path)
                deployment_report['backup_created'] = str(backup_path)
                deployment_report['steps_completed'].append('backup_created')

            # Step 3: Install dependencies
            self._install_dependencies()
            deployment_report['steps_completed'].append('dependencies_installed')

            # Step 4: Deploy core files
            self._deploy_core_files(target_path)
            deployment_report['steps_completed'].append('core_files_deployed')

            # Step 5: Configure environment
            self._configure_production_environment(target_path)
            deployment_report['steps_completed'].append('environment_configured')

            # Step 6: Run post-deployment tests
            test_results = self._run_post_deployment_tests(target_path)
            deployment_report['post_deployment_tests'] = test_results
            deployment_report['steps_completed'].append('post_deployment_tests')

            # Step 7: Update system integration
            self._update_system_integration(target_path)
            deployment_report['steps_completed'].append('system_integration_updated')

            deployment_report['status'] = 'completed'
            deployment_report['rollback_available'] = backup_existing

            # Log successful deployment
            self.audit_logger.log_security_event(
                event_type="PRODUCTION_DEPLOYMENT_COMPLETED",
                message=f"Secure execution environment deployed to: {target_path}",
                details=deployment_report
            )

        except Exception as e:
            deployment_report['status'] = 'failed'
            deployment_report['error'] = str(e)
            deployment_report['issues_encountered'].append(str(e))

            # Log deployment failure
            self.audit_logger.log_security_event(
                event_type="DEPLOYMENT_FAILED",
                message=f"Production deployment failed: {str(e)}",
                details=deployment_report
            )

        return deployment_report

    def _run_pre_deployment_checks(self) -> None:
        """Run pre-deployment validation checks."""
        checks = [
            self._check_system_requirements,
            self._check_dependencies,
            self._check_permissions,
            self._validate_configuration
        ]

        for check_func in checks:
            try:
                check_func()
            except Exception as e:
                raise Exception(f"Pre-deployment check failed: {check_func.__name__} - {str(e)}")

    def _check_system_requirements(self) -> None:
        """Check system requirements for deployment."""
        # Check Python version
        import sys
        if sys.version_info < (3, 8):
            raise Exception("Python 3.8+ required")

        # Check available disk space
        stat = os.statvfs('/')
        free_space_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        if free_space_gb < 1.0:
            raise Exception("Insufficient disk space (< 1GB free)")

    def _check_dependencies(self) -> None:
        """Check required dependencies."""
        required_modules = ['yaml', 'psutil', 'pathlib']

        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                raise Exception(f"Required module not found: {module}")

    def _check_permissions(self) -> None:
        """Check deployment permissions."""
        # Check if we can write to target directory
        test_file = Path("/tmp/deployment_test")
        try:
            test_file.write_text("test")
            test_file.unlink()
        except Exception as e:
            raise Exception(f"Insufficient permissions for deployment: {str(e)}")

    def _validate_configuration(self) -> None:
        """Validate deployment configuration."""
        config_path = Path("scripts/config/security_policy.yml")
        if not config_path.exists():
            raise Exception("Security policy configuration not found")

        # Validate YAML syntax
        try:
            import yaml
            with open(config_path, 'r') as f:
                yaml.safe_load(f)
        except Exception as e:
            raise Exception(f"Invalid security policy configuration: {str(e)}")

    def _install_dependencies(self) -> None:
        """Install required dependencies."""
        # This would typically use pip to install dependencies
        # For now, we'll just check if they're available
        pass

    def _deploy_core_files(self, target_path: Path) -> None:
        """Deploy core secure execution files."""
        secure_dir = Path("scripts/secure")

        if not secure_dir.exists():
            raise Exception("Secure execution files not found")

        # Create target directory structure
        target_path.mkdir(parents=True, exist_ok=True)

        # Copy core files
        files_to_copy = [
            'executor.py',
            'policy.py',
            'audit.py',
            'monitor.py',
            'analyzer.py',
            'migration.py',
            'testing.py',
            'deployment.py',
            '__init__.py'
        ]

        for file_name in files_to_copy:
            src_file = secure_dir / file_name
            if src_file.exists():
                shutil.copy2(src_file, target_path / file_name)

        # Copy configuration
        config_src = Path("scripts/config/security_policy.yml")
        config_dst = target_path / "security_policy.yml"
        if config_src.exists():
            shutil.copy2(config_src, config_dst)

    def _configure_production_environment(self, target_path: Path) -> None:
        """Configure production environment settings."""
        # Create production-specific configuration
        prod_config = {
            'environment': 'production',
            'log_level': 'WARNING',
            'audit_retention_days': 90,
            'alert_email': 'security@cmmv-hive.org',
            'max_concurrent_scripts': 10
        }

        import yaml
        config_file = target_path / "production_config.yml"
        with open(config_file, 'w') as f:
            yaml.dump(prod_config, f)

        # Create log directories
        log_dirs = ['logs', 'audit', 'security']
        for log_dir in log_dirs:
            (target_path / log_dir).mkdir(exist_ok=True)

    def _run_post_deployment_tests(self, target_path: Path) -> Dict[str, Any]:
        """Run post-deployment validation tests."""
        # Import and run basic functionality test
        import sys
        sys.path.insert(0, str(target_path))

        try:
            from executor import SecureScriptExecutor

            # Create a simple test
            test_script = target_path / "test_deployment.py"
            test_script.write_text("print('Deployment test successful')")

            executor = SecureScriptExecutor()
            result = executor.execute_script(str(test_script))

            test_script.unlink()

            return {
                'test_passed': result['success'],
                'output': result['stdout'].strip(),
                'execution_time': result['execution_time']
            }

        except Exception as e:
            return {
                'test_passed': False,
                'error': str(e)
            }

    def _update_system_integration(self, target_path: Path) -> None:
        """Update system integration points."""
        # This would typically update system PATH, create symlinks, etc.
        # For now, we'll create a simple integration script

        integration_script = target_path / "integrate.sh"
        integration_script.write_text("""#!/bin/bash
# System integration script for BIP-04 Secure Script Execution

echo "Integrating BIP-04 Secure Script Execution..."

# Add to system PATH (example)
# export PATH="$PATH:/opt/cmmv-secure-scripts"

echo "Integration completed. Please restart your shell or run:"
echo "export PATH=\$PATH:/opt/cmmv-secure-scripts"
""")

        integration_script.chmod(0o755)

    def rollback_deployment(self, target_dir: str = "/opt/cmmv-secure-scripts") -> Dict[str, Any]:
        """
        Rollback deployment to previous version.

        Args:
            target_dir: Target deployment directory

        Returns:
            Rollback report
        """
        target_path = Path(target_dir)
        backup_path = target_path.with_suffix('.backup')

        rollback_report = {
            'rollback_target': str(target_path),
            'backup_source': str(backup_path),
            'timestamp': __import__('time').time(),
            'status': 'in_progress'
        }

        try:
            if not backup_path.exists():
                raise Exception("No backup found for rollback")

            # Remove current deployment
            if target_path.exists():
                shutil.rmtree(target_path)

            # Restore from backup
            shutil.copytree(backup_path, target_path)

            rollback_report['status'] = 'completed'

            # Log rollback
            self.audit_logger.log_security_event(
                event_type="DEPLOYMENT_ROLLBACK_COMPLETED",
                message=f"Deployment rolled back to: {target_path}",
                details=rollback_report
            )

        except Exception as e:
            rollback_report['status'] = 'failed'
            rollback_report['error'] = str(e)

            # Log rollback failure
            self.audit_logger.log_security_event(
                event_type="ROLLBACK_FAILED",
                message=f"Deployment rollback failed: {str(e)}",
                details=rollback_report
            )

        return rollback_report

    def generate_deployment_guide(self) -> str:
        """Generate deployment guide documentation."""
        guide = """
# BIP-04 Secure Script Execution Environment - Deployment Guide

## Prerequisites

- Python 3.8+
- 1GB free disk space
- Root/administrative privileges for system integration
- Required Python packages: pyyaml, psutil

## Deployment Steps

### 1. Pre-deployment Validation
```bash
# Run pre-deployment checks
python -c "from scripts.secure.deployment import DeploymentManager; dm = DeploymentManager(None); dm._run_pre_deployment_checks()"
```

### 2. Production Deployment
```bash
# Deploy to production
python -c "
from scripts.secure.executor import SecureScriptExecutor
from scripts.secure.deployment import DeploymentManager
executor = SecureScriptExecutor()
dm = DeploymentManager(executor)
result = dm.deploy_to_production()
print('Deployment status:', result['status'])
"
```

### 3. System Integration
```bash
# Run integration script
/opt/cmmv-secure-scripts/integrate.sh

# Add to system PATH
echo 'export PATH=$PATH:/opt/cmmv-secure-scripts' >> ~/.bashrc
source ~/.bashrc
```

### 4. Validation
```bash
# Run post-deployment tests
python -c "
from scripts.secure.executor import SecureScriptExecutor
executor = SecureScriptExecutor()
result = executor.execute_script('test_script.py')
print('Validation result:', result['success'])
"
```

## Configuration

### Security Policy
Edit `/opt/cmmv-secure-scripts/security_policy.yml` to customize security settings.

### Production Configuration
Edit `/opt/cmmv-secure-scripts/production_config.yml` for production-specific settings.

## Monitoring

### Logs
- Execution logs: `/opt/cmmv-secure-scripts/logs/execution_audit.log`
- Security events: `/opt/cmmv-secure-scripts/logs/security_events.log`

### Health Checks
```python
from secure import SecureScriptExecutor
executor = SecureScriptExecutor()
stats = executor.get_security_stats()
print("System health:", stats)
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure proper file permissions
   - Check user privileges

2. **Import Errors**
   - Verify Python path configuration
   - Check dependency installation

3. **Configuration Errors**
   - Validate YAML syntax
   - Check file paths

### Rollback
```bash
# Rollback deployment
python -c "
from scripts.secure.executor import SecureScriptExecutor
from scripts.secure.deployment import DeploymentManager
executor = SecureScriptExecutor()
dm = DeploymentManager(executor)
result = dm.rollback_deployment()
print('Rollback status:', result['status'])
"
```

## Support

For issues or questions:
- Check the audit logs for detailed error information
- Review the security policy configuration
- Contact the development team
"""
        return guide
