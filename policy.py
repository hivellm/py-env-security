"""
Security policy management for the secure script execution environment.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List
from exceptions import PolicyViolationException

class SecurityPolicy:
    """Manages security policy configuration."""

    def __init__(self, policy_file: str = "scripts/config/security_policy.yml"):
        self.policy_file = Path(policy_file)
        self._policy: Dict[str, Any] = {}
        self._load_policy()

    def _load_policy(self) -> None:
        """Load and validate the security policy from YAML file."""
        try:
            with open(self.policy_file, 'r', encoding='utf-8') as f:
                self._policy = yaml.safe_load(f)
        except FileNotFoundError:
            raise PolicyViolationException(f"Security policy file not found: {self.policy_file}")
        except yaml.YAMLError as e:
            raise PolicyViolationException(f"Invalid YAML in security policy: {e}")

        self._validate_policy()

    def _validate_policy(self) -> None:
        """Validate the loaded security policy."""
        # Handle both flat and nested YAML structures
        if 'security' in self._policy:
            # Nested structure: security: {execution: {...}, ...}
            policy_root = self._policy['security']
        else:
            # Flat structure: execution: {...}, ...
            policy_root = self._policy

        required_sections = ['execution', 'filesystem', 'network', 'monitoring']
        for section in required_sections:
            if section not in policy_root:
                raise PolicyViolationException(f"Missing required section: {section}")

        # Validate execution limits
        exec_config = policy_root['execution']
        if exec_config.get('timeout_seconds', 0) <= 0:
            raise PolicyViolationException("Invalid timeout_seconds value")
        if exec_config.get('cpu_seconds', 0) <= 0:
            raise PolicyViolationException("Invalid cpu_seconds value")
        if exec_config.get('memory_mb', 0) <= 0:
            raise PolicyViolationException("Invalid memory_mb value")

    def _get_policy_root(self) -> Dict[str, Any]:
        """Get the root policy dictionary, handling nested structure."""
        if 'security' in self._policy:
            return self._policy['security']
        return self._policy

    def get_execution_limits(self) -> Dict[str, Any]:
        """Get execution resource limits."""
        return self._get_policy_root()['execution'].copy()

    def get_filesystem_policy(self) -> Dict[str, Any]:
        """Get filesystem access policy."""
        return self._get_policy_root()['filesystem'].copy()

    def get_network_policy(self) -> Dict[str, Any]:
        """Get network access policy."""
        return self._get_policy_root()['network'].copy()

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return self._get_policy_root()['monitoring'].copy()

    def get_static_analysis_policy(self) -> Dict[str, Any]:
        """Get static analysis configuration."""
        return self._get_policy_root().get('static_analysis', {}).copy()

    def is_path_allowed(self, path: str) -> bool:
        """Check if a filesystem path is allowed.

        Security Policy:
        - Paths are normalized and resolved to canonical form
        - Symlinks are resolved to their target
        - Only exact matches or subdirectories of allowed paths are permitted
        - Empty allowed_paths list denies all access (secure by default)
        """
        import os
        from pathlib import Path

        fs_policy = self.get_filesystem_policy()
        allowed_paths = fs_policy.get('allowed_paths', [])

        # Empty list means deny all paths (secure by default)
        if not allowed_paths:
            return False

        try:
            # Resolve the input path to its absolute, canonical form
            input_path = Path(path).resolve()

            # Pre-resolve all allowed paths for efficiency
            resolved_allowed_paths = [Path(p).resolve() for p in allowed_paths]

            for allowed_path in resolved_allowed_paths:
                try:
                    # Check if the allowed_path is a parent of the input_path
                    common = os.path.commonpath([input_path, allowed_path])
                    if Path(common) == allowed_path:
                        return True
                except ValueError:
                    # This can happen if paths are on different drives on Windows
                    continue

        except (OSError, ValueError):
            # If path cannot be resolved (e.g., does not exist), deny access
            return False

        return False

    def is_operation_blocked(self, operation: str) -> bool:
        """Check if a filesystem operation is blocked."""
        fs_policy = self.get_filesystem_policy()
        blocked_ops = fs_policy.get('blocked_operations', [])
        return operation in blocked_ops

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a network domain is allowed.

        Security Policy:
        - If allowed_domains is empty: DENY ALL domains (secure by default)
        - If allowed_domains contains domains: only those domains are allowed
        - Domain matching is case-insensitive and includes subdomains
        """
        net_policy = self.get_network_policy()
        allowed_domains = net_policy.get('allowed_domains', [])

        # Empty list means deny all domains (secure by default)
        if len(allowed_domains) == 0:
            return False

        # Check if domain matches any allowed domain (case-insensitive)
        domain_lower = domain.lower()
        for allowed_domain in allowed_domains:
            allowed_lower = allowed_domain.lower()
            # Allow exact match or subdomain (e.g., api.example.com matches example.com)
            if domain_lower == allowed_lower or domain_lower.endswith('.' + allowed_lower):
                return True

        return False

    def is_port_blocked(self, port: int) -> bool:
        """Check if a network port is blocked."""
        net_policy = self.get_network_policy()
        blocked_ports = net_policy.get('blocked_ports', [])
        return port in blocked_ports

    def should_alert(self, metric: str, value: float) -> bool:
        """Check if an alert should be triggered for a metric."""
        monitoring_config = self.get_monitoring_config()
        thresholds = monitoring_config.get('alert_thresholds', {})
        threshold = thresholds.get(metric)
        return threshold is not None and value >= threshold
