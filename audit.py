"""
Audit logging system for the secure script execution environment.
"""

import json
import hashlib
import logging
import hmac
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import subprocess

class AuditLogger:
    """Comprehensive audit logging for script execution."""

    def __init__(self, log_dir: str = "scripts/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.execution_log = self.log_dir / "execution_audit.log"
        self.security_log = self.log_dir / "security_events.log"

        # Tamper-evident logging setup
        self.integrity_log = self.log_dir / "log_integrity.dat"
        self._log_secret_key = self._generate_log_key()
        self._previous_hash = self._load_previous_hash()

        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Remove file handlers that produce non-JSON lines; keep standard logging for console only
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)

    def log_execution(self, script_path: str, args: Optional[List[str]] = None,
                     result: subprocess.CompletedProcess = None,
                     execution_time: float = 0.0, success: bool = False,
                     resource_usage: Optional[Dict[str, Any]] = None) -> None:
        """Log script execution details."""

        # Calculate script hash for integrity verification
        script_hash = self._calculate_file_hash(script_path)

        # Prepare execution record
        execution_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'script_path': script_path,
            'script_hash': script_hash,
            'args': args or [],
            'return_code': result.returncode if result else None,
            'stdout_hash': self._hash_content(result.stdout) if result and result.stdout else None,
            'stderr_hash': self._hash_content(result.stderr) if result and result.stderr else None,
            'execution_time': execution_time,
            'success': success,
            'resource_usage': resource_usage or {}
        }

        # Write to execution audit log
        with open(self.execution_log, 'a', encoding='utf-8') as f:
            json.dump(execution_record, f, ensure_ascii=False)
            f.write('\n')

        # Optional console log for observability (no file noise)
        status = "SUCCESS" if success else "FAILED"
        print(
            json.dumps({
                'type': 'EXECUTION_SUMMARY',
                'status': status,
                'script_path': script_path,
                'execution_time': execution_time,
                'script_hash_prefix': script_hash[:8]
            }), flush=True
        )

        # Alert on security issues
        if not success or execution_time > 250:  # Configurable threshold
            self._send_security_alert(execution_record)

    def log_security_event(self, event_type: str, message: str,
                          script_path: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """Log security-related events."""

        event_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'message': message,
            'script_path': script_path,
            'details': details or {}
        }

        # Add tamper-evident hash chain
        entry_hash = self._calculate_entry_hash(event_record)
        event_record['entry_hash'] = entry_hash

        # Calculate chain hash
        if self._previous_hash:
            chain_hash = hashlib.sha256((self._previous_hash + entry_hash).encode()).hexdigest()
            event_record['chain_hash'] = chain_hash
            self._previous_hash = chain_hash
        else:
            # First entry in chain
            event_record['chain_hash'] = entry_hash
            self._previous_hash = entry_hash

        # Write to security events log as JSON only
        with open(self.security_log, 'a', encoding='utf-8') as f:
            json.dump(event_record, f, ensure_ascii=False)
            f.write('\n')

        # Update integrity chain
        self._update_integrity_chain(entry_hash)

        # Also log to standard logging for real-time monitoring (but not to file)
        print(f"[SECURITY] {event_type}: {message}", flush=True)

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of script file."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (FileNotFoundError, IOError):
            return "FILE_NOT_ACCESSIBLE"

    def _hash_content(self, content: str) -> str:
        """Calculate SHA256 hash of content string."""
        if content:
            return hashlib.sha256(content.encode('utf-8')).hexdigest()
        return None

    def _send_security_alert(self, execution_record: Dict[str, Any]) -> None:
        """Send security alert for concerning execution."""
        alert_message = (
            f"Security Alert: Script execution anomaly | "
            f"Script: {execution_record['script_path']} | "
            f"Time: {execution_record['execution_time']:.2f}s | "
            f"Success: {execution_record['success']}"
        )

        self.log_security_event(
            event_type="EXECUTION_ANOMALY",
            message=alert_message,
            script_path=execution_record['script_path'],
            details={
                'execution_time': execution_record['execution_time'],
                'return_code': execution_record['return_code'],
                'resource_usage': execution_record['resource_usage']
            }
        )

    def get_execution_history(self, script_path: Optional[str] = None,
                            limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve execution history, optionally filtered by script."""
        executions = []

        try:
            if not self.execution_log.exists():
                return executions

            with open(self.execution_log, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                        if script_path is None or record.get('script_path') == script_path:
                            executions.append(record)
                            if len(executions) >= limit:
                                break
                    except json.JSONDecodeError as e:
                        # Log the error but continue processing other lines
                        print(f"Warning: Failed to parse JSON at line {line_num}: {e}")
                        continue

        except (FileNotFoundError, IOError):
            # File doesn't exist or can't be read
            pass

        return executions

    def get_security_events(self, event_type: Optional[str] = None,
                          limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve security events, optionally filtered by type."""
        events = []

        try:
            if not self.security_log.exists():
                return events

            with open(self.security_log, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                        if event_type is None or record.get('event_type') == event_type:
                            events.append(record)
                            if len(events) >= limit:
                                break
                    except json.JSONDecodeError as e:
                        # Log the error but continue processing other lines
                        print(f"Warning: Failed to parse JSON at line {line_num}: {e}")
                        continue

        except (FileNotFoundError, IOError):
            # File doesn't exist or can't be read
            pass

        return events

    def _generate_log_key(self) -> bytes:
        """Generate or load a secret key for log integrity."""
        key_file = self.log_dir / ".log_key"
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate a new key
            key = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).digest()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Secure the key file
            key_file.chmod(0o600)
            return key

    def _load_previous_hash(self) -> str:
        """Load the previous log hash for chain validation."""
        if self.integrity_log.exists():
            try:
                with open(self.integrity_log, 'r') as f:
                    data = json.load(f)
                    return data.get('last_hash', '')
            except (json.JSONDecodeError, IOError):
                return ''
        return ''

    def _calculate_entry_hash(self, entry_data: Dict[str, Any]) -> str:
        """Calculate hash for a log entry."""
        # Create a canonical JSON representation
        canonical_json = json.dumps(entry_data, sort_keys=True, separators=(',', ':'))
        # Use HMAC for integrity
        return hmac.new(self._log_secret_key, canonical_json.encode(), hashlib.sha256).hexdigest()

    def _update_integrity_chain(self, entry_hash: str) -> None:
        """Update the integrity chain with new hash."""
        chain_hash = hashlib.sha256((self._previous_hash + entry_hash).encode()).hexdigest()

        integrity_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'last_hash': chain_hash,
            'previous_hash': self._previous_hash,
            'entry_hash': entry_hash
        }

        with open(self.integrity_log, 'w') as f:
            json.dump(integrity_data, f, indent=2)

        self._previous_hash = chain_hash

    def verify_log_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the audit logs."""
        verification_result = {
            'security_events_integrity': True,
            'execution_audit_integrity': True,
            'chain_valid': True,
            'tampered_entries': [],
            'total_entries_checked': 0,
            'errors': []
        }

        # Verify security events log
        verification_result.update(self._verify_log_file_integrity(
            self.security_log, 'security_events_integrity'
        ))

        # Verify execution audit log
        verification_result.update(self._verify_log_file_integrity(
            self.execution_log, 'execution_audit_integrity'
        ))

        return verification_result

    def _verify_log_file_integrity(self, log_file: Path, result_key: str) -> Dict[str, Any]:
        """Verify integrity of a specific log file."""
        result = {result_key: True, 'tampered_entries': [], 'total_entries': 0, 'errors': []}

        if not log_file.exists():
            return result

        expected_previous_hash = ''

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                        result['total_entries'] += 1

                        # Calculate expected hash for this entry
                        entry_hash = self._calculate_entry_hash(entry)

                        # Verify chain
                        if expected_previous_hash:
                            chain_hash = hashlib.sha256((expected_previous_hash + entry_hash).encode()).hexdigest()
                            stored_chain_hash = entry.get('chain_hash', '')
                            if chain_hash != stored_chain_hash:
                                result[result_key] = False
                                result['tampered_entries'].append({
                                    'line': line_num,
                                    'entry_hash': entry_hash,
                                    'expected_chain': chain_hash,
                                    'stored_chain': stored_chain_hash
                                })

                        expected_previous_hash = entry_hash

                    except json.JSONDecodeError as e:
                        result['errors'].append(f"Line {line_num}: {e}")
                        continue

        except IOError as e:
            result['errors'].append(f"File read error: {e}")

        return result
