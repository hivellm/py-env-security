"""
Script migration utilities for BIP-04 Secure Script Execution Environment.
"""

import os
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from .executor import SecureScriptExecutor
from analyzer import SecurityAnalyzer
from audit import AuditLogger

class ScriptMigrationManager:
    """Manages migration of existing scripts to secure execution environment."""

    def __init__(self, secure_executor: SecureScriptExecutor):
        self.executor = secure_executor
        self.analyzer = SecurityAnalyzer(self.executor.audit_logger)
        self.audit_logger = self.executor.audit_logger

    def analyze_script_for_migration(self, script_path: str) -> Dict[str, Any]:
        """
        Analyze a script to determine migration requirements.

        Args:
            script_path: Path to the script to analyze

        Returns:
            Analysis report with migration recommendations
        """
        script_path = Path(script_path)

        analysis = {
            'script_path': str(script_path),
            'migration_required': False,
            'issues_found': [],
            'migration_steps': [],
            'estimated_effort': 'low',
            'compatibility_score': 100
        }

        # Perform static analysis
        try:
            static_analysis = self.analyzer.analyze_script(str(script_path))

            if static_analysis['vulnerabilities_found'] > 0:
                analysis['migration_required'] = True
                analysis['issues_found'].extend([
                    f"{v['type']}: {v['description']}"
                    for v in static_analysis['vulnerabilities']
                ])

            # Check for common migration issues
            migration_issues = self._identify_migration_issues(script_path)
            if migration_issues:
                analysis['migration_required'] = True
                analysis['issues_found'].extend(migration_issues)

            # Estimate effort
            analysis['estimated_effort'] = self._estimate_migration_effort(
                static_analysis, migration_issues
            )

            # Calculate compatibility score
            analysis['compatibility_score'] = self._calculate_compatibility_score(
                static_analysis, migration_issues
            )

        except Exception as e:
            analysis['issues_found'].append(f"Analysis error: {str(e)}")
            analysis['migration_required'] = True

        # Generate migration steps
        analysis['migration_steps'] = self._generate_migration_steps(analysis)

        return analysis

    def _identify_migration_issues(self, script_path: Path) -> List[str]:
        """Identify common migration issues in the script."""
        issues = []

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for absolute paths that might need adjustment
            if '/usr/' in content or '/etc/' in content:
                issues.append("Contains absolute system paths that may need adjustment")

            # Check for hardcoded file paths
            if 'open(' in content and ('/' in content or '\\' in content):
                issues.append("Contains hardcoded file paths that may violate security policy")

            # Check for subprocess usage
            if 'subprocess.' in content:
                issues.append("Uses subprocess module - may need security review")

            # Check for network operations
            if 'socket.' in content or 'urllib' in content or 'requests' in content:
                issues.append("Contains network operations - may require domain whitelisting")

            # Check for environment variable usage
            if 'os.environ' in content:
                issues.append("Accesses environment variables - may need security review")

        except Exception as e:
            issues.append(f"Could not analyze script content: {str(e)}")

        return issues

    def _estimate_migration_effort(self, static_analysis: Dict[str, Any],
                                 migration_issues: List[str]) -> str:
        """Estimate the effort required for migration."""
        total_issues = len(static_analysis.get('vulnerabilities', [])) + len(migration_issues)

        if total_issues == 0:
            return 'none'
        elif total_issues <= 2:
            return 'low'
        elif total_issues <= 5:
            return 'medium'
        else:
            return 'high'

    def _calculate_compatibility_score(self, static_analysis: Dict[str, Any],
                                     migration_issues: List[str]) -> int:
        """Calculate compatibility score (0-100)."""
        base_score = 100
        vulnerabilities = static_analysis.get('vulnerabilities', [])

        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln['severity'] == 'critical':
                base_score -= 20
            elif vuln['severity'] == 'high':
                base_score -= 10
            elif vuln['severity'] == 'medium':
                base_score -= 5
            else:
                base_score -= 2

        # Deduct points for migration issues
        base_score -= len(migration_issues) * 5

        return max(0, min(100, base_score))

    def _generate_migration_steps(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate specific migration steps."""
        steps = []

        if not analysis['migration_required']:
            steps.append("No migration required - script is compatible")
            return steps

        steps.append("1. Review security analysis report and understand identified issues")

        if any('subprocess' in issue for issue in analysis['issues_found']):
            steps.append("2. Review subprocess usage for security implications")

        if any('network' in issue.lower() for issue in analysis['issues_found']):
            steps.append("3. Configure network access permissions in security policy")

        if any('file' in issue.lower() and 'path' in issue.lower()
               for issue in analysis['issues_found']):
            steps.append("4. Update file paths to use allowed directories")

        if any('environment' in issue.lower() for issue in analysis['issues_found']):
            steps.append("5. Review environment variable usage for security compliance")

        steps.append("6. Test script execution in secure environment")
        steps.append("7. Monitor execution logs for security violations")
        steps.append("8. Update documentation with secure execution requirements")

        return steps

    def migrate_script(self, script_path: str, target_path: Optional[str] = None,
                      backup: bool = True) -> Dict[str, Any]:
        """
        Migrate a script to be compatible with secure execution.

        Args:
            script_path: Path to the script to migrate
            target_path: Optional target path for migrated script
            backup: Whether to create a backup of the original script

        Returns:
            Migration report
        """
        script_path = Path(script_path)
        if not script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")

        if target_path is None:
            target_path = script_path

        migration_report = {
            'original_script': str(script_path),
            'target_script': str(target_path),
            'backup_created': False,
            'changes_made': [],
            'migration_successful': False,
            'warnings': []
        }

        try:
            # Create backup if requested
            if backup and str(target_path) == str(script_path):
                backup_path = script_path.with_suffix('.bak')
                shutil.copy2(script_path, backup_path)
                migration_report['backup_created'] = True
                migration_report['backup_path'] = str(backup_path)

            # Read original content
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Apply migration transformations
            new_content, changes = self._apply_migration_transforms(content)

            # Write migrated content
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(new_content)

            migration_report['changes_made'] = changes
            migration_report['migration_successful'] = True

            # Log migration
            self.audit_logger.log_security_event(
                event_type="SCRIPT_MIGRATION",
                message=f"Script migrated for secure execution: {script_path}",
                script_path=str(script_path),
                details=migration_report
            )

        except Exception as e:
            migration_report['migration_successful'] = False
            migration_report['error'] = str(e)

            self.audit_logger.log_security_event(
                event_type="MIGRATION_ERROR",
                message=f"Script migration failed: {script_path} - {str(e)}",
                script_path=str(script_path),
                details={'error': str(e)}
            )

        return migration_report

    def _apply_migration_transforms(self, content: str) -> tuple[str, List[str]]:
        """Apply migration transformations to script content."""
        changes = []

        # Add secure execution header
        if not content.startswith('#!/usr/bin/env python3'):
            content = '#!/usr/bin/env python3\n' + content
            changes.append("Added shebang line")

        # This is a placeholder for more sophisticated transformations
        # In a real implementation, this would apply specific fixes for
        # identified security issues

        return content, changes

    def generate_migration_report(self, scripts_dir: str) -> Dict[str, Any]:
        """
        Generate a comprehensive migration report for all scripts in a directory.

        Args:
            scripts_dir: Directory containing scripts to analyze

        Returns:
            Comprehensive migration report
        """
        scripts_dir = Path(scripts_dir)
        if not scripts_dir.exists():
            raise FileNotFoundError(f"Scripts directory not found: {scripts_dir}")

        report = {
            'directory': str(scripts_dir),
            'total_scripts': 0,
            'migration_required': 0,
            'migration_completed': 0,
            'compatibility_score_avg': 0,
            'scripts_analysis': [],
            'summary': {}
        }

        script_files = list(scripts_dir.rglob('*.py'))
        report['total_scripts'] = len(script_files)

        total_compatibility = 0

        for script_file in script_files:
            analysis = self.analyze_script_for_migration(str(script_file))
            report['scripts_analysis'].append(analysis)

            if analysis['migration_required']:
                report['migration_required'] += 1

            total_compatibility += analysis['compatibility_score']

        if report['total_scripts'] > 0:
            report['compatibility_score_avg'] = total_compatibility / report['total_scripts']

        # Generate summary
        report['summary'] = {
            'migration_readiness': self._calculate_migration_readiness(report),
            'risk_assessment': self._assess_migration_risk(report),
            'recommended_approach': self._recommend_migration_approach(report)
        }

        return report

    def _calculate_migration_readiness(self, report: Dict[str, Any]) -> str:
        """Calculate overall migration readiness."""
        if report['total_scripts'] == 0:
            return 'unknown'

        migration_ratio = report['migration_required'] / report['total_scripts']
        avg_compatibility = report['compatibility_score_avg']

        if migration_ratio < 0.2 and avg_compatibility > 80:
            return 'high'
        elif migration_ratio < 0.5 and avg_compatibility > 60:
            return 'medium'
        else:
            return 'low'

    def _assess_migration_risk(self, report: Dict[str, Any]) -> str:
        """Assess the risk level of the migration."""
        high_risk_scripts = sum(1 for s in report['scripts_analysis']
                              if s['estimated_effort'] in ['high', 'medium']
                              and s['compatibility_score'] < 70)

        if high_risk_scripts == 0:
            return 'low'
        elif high_risk_scripts <= 2:
            return 'medium'
        else:
            return 'high'

    def _recommend_migration_approach(self, report: Dict[str, Any]) -> str:
        """Recommend migration approach based on analysis."""
        readiness = report['summary']['migration_readiness']
        risk = report['summary']['risk_assessment']

        if readiness == 'high' and risk == 'low':
            return 'parallel_migration'
        elif readiness == 'medium':
            return 'phased_migration'
        else:
            return 'incremental_migration'
