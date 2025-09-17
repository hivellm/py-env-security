"""
Static analysis tools for script security validation.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
from audit import AuditLogger

class SecurityAnalyzer:
    """Static analysis tool for detecting security vulnerabilities in scripts."""

    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.vulnerabilities: List[Dict[str, Any]] = []

        # Security patterns to detect
        self.dangerous_patterns = {
            'shell_execution': [
                r'os\.system\s*\(',
                r'subprocess\.(call|Popen|run)\s*\(',
                r'os\.popen\s*\(',
                r'os\.execv\w*\s*\('
            ],
            'file_operations': [
                r'open\s*\(',
                r'os\.remove\s*\(',
                r'os\.rmdir\s*\(',
                r'shutil\.rmtree\s*\(',
                r'os\.chmod\s*\(',
                r'os\.chown\s*\('
            ],
            'network_operations': [
                r'socket\.',
                r'urllib\.',
                r'http\.',
                r'requests\.',
                r'urllib3\.'
            ],
            'dangerous_imports': [
                r'import\s+(os|subprocess|shutil|socket|urllib)',
                r'from\s+(os|subprocess|shutil|socket|urllib)'
            ],
            'code_execution': [
                r'eval\s*\(',
                r'exec\s*\(',
                r'compile\s*\(',
                r'__import__\s*\('
            ]
        }

    def analyze_script(self, script_path: str) -> Dict[str, Any]:
        """
        Perform static analysis on a script.

        Args:
            script_path: Path to the script to analyze

        Returns:
            Analysis results with vulnerabilities found
        """
        script_path = Path(script_path)
        self.vulnerabilities = []

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Perform various analysis checks
            self._check_dangerous_patterns(content, str(script_path))
            self._check_ast_security(script_path)
            self._check_imports_security(content, str(script_path))

            analysis_result = {
                'script_path': str(script_path),
                'vulnerabilities_found': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities.copy(),
                'risk_level': self._calculate_risk_level(),
                'recommendations': self._generate_recommendations()
            }

            # Log analysis results
            if self.vulnerabilities:
                self.audit_logger.log_security_event(
                    event_type="STATIC_ANALYSIS_VULNERABILITIES",
                    message=f"Found {len(self.vulnerabilities)} security vulnerabilities",
                    script_path=str(script_path),
                    details=analysis_result
                )

            return analysis_result

        except Exception as e:
            error_result = {
                'script_path': str(script_path),
                'error': str(e),
                'vulnerabilities_found': 0,
                'vulnerabilities': [],
                'risk_level': 'unknown',
                'recommendations': ['Fix script syntax errors before analysis']
            }

            self.audit_logger.log_security_event(
                event_type="ANALYSIS_ERROR",
                message=f"Static analysis failed: {str(e)}",
                script_path=str(script_path)
            )

            return error_result

    def _check_dangerous_patterns(self, content: str, script_path: str) -> None:
        """Check for dangerous code patterns."""
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for category, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line):
                        vulnerability = {
                            'type': category,
                            'pattern': pattern,
                            'line': line_num,
                            'code': line.strip(),
                            'severity': self._get_pattern_severity(category),
                            'description': self._get_pattern_description(category, pattern)
                        }
                        self.vulnerabilities.append(vulnerability)

    def _check_ast_security(self, script_path: Path) -> None:
        """Analyze the Abstract Syntax Tree for security issues."""
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile', '__import__']:
                            vulnerability = {
                                'type': 'code_execution',
                                'pattern': f'{func_name}()',
                                'line': getattr(node, 'lineno', 0),
                                'code': f'{func_name}() call detected',
                                'severity': 'high',
                                'description': f'Dangerous {func_name}() function call'
                            }
                            self.vulnerabilities.append(vulnerability)

                elif isinstance(node, ast.Import):
                    # Check for dangerous imports
                    for alias in node.names:
                        if alias.name in ['os', 'subprocess', 'socket']:
                            vulnerability = {
                                'type': 'dangerous_import',
                                'pattern': f'import {alias.name}',
                                'line': node.lineno,
                                'code': f'import {alias.name}',
                                'severity': 'medium',
                                'description': f'Potentially dangerous import: {alias.name}'
                            }
                            self.vulnerabilities.append(vulnerability)

        except SyntaxError:
            # AST parsing will fail for invalid Python, but that's handled in the main method
            pass

    def _check_imports_security(self, content: str, script_path: str) -> None:
        """Check for insecure import patterns."""
        # This is already covered by the pattern matching, but we could add more sophisticated checks here
        pass

    def _get_pattern_severity(self, category: str) -> str:
        """Get severity level for a vulnerability category."""
        severity_map = {
            'shell_execution': 'critical',
            'code_execution': 'critical',
            'file_operations': 'high',
            'network_operations': 'medium',
            'dangerous_imports': 'low'
        }
        return severity_map.get(category, 'medium')

    def _get_pattern_description(self, category: str, pattern: str) -> str:
        """Get description for a vulnerability pattern."""
        descriptions = {
            'shell_execution': 'Shell command execution can lead to command injection vulnerabilities',
            'code_execution': 'Dynamic code execution poses severe security risks',
            'file_operations': 'File system operations may allow unauthorized access',
            'network_operations': 'Network operations may leak sensitive data',
            'dangerous_imports': 'Imports of potentially dangerous modules'
        }
        return descriptions.get(category, 'Security vulnerability detected')

    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level based on vulnerabilities found."""
        if not self.vulnerabilities:
            return 'low'

        critical_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'critical')
        high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'high')

        if critical_count > 0:
            return 'critical'
        elif high_count > 2:
            return 'high'
        elif high_count > 0 or len(self.vulnerabilities) > 3:
            return 'medium'
        else:
            return 'low'

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        if not self.vulnerabilities:
            recommendations.append("No security issues found - script appears safe")
            return recommendations

        # Count vulnerabilities by type
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        # Generate specific recommendations
        if 'shell_execution' in type_counts:
            recommendations.append("Avoid shell command execution - use subprocess with explicit arguments")

        if 'code_execution' in type_counts:
            recommendations.append("Never use eval(), exec(), or compile() with user input")

        if 'file_operations' in type_counts:
            recommendations.append("Implement proper file access controls and validation")

        if 'network_operations' in type_counts:
            recommendations.append("Validate all network endpoints and use HTTPS for secure communication")

        if 'dangerous_imports' in type_counts:
            recommendations.append("Minimize use of potentially dangerous modules or sandbox their usage")

        # General recommendations
        recommendations.extend([
            "Implement input validation for all user-provided data",
            "Use principle of least privilege for script execution",
            "Regular security audits and updates",
            "Consider using static analysis tools in CI/CD pipeline"
        ])

        return recommendations
