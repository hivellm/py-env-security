# BIP-04 Administrator Guide

## System Administration Guide for Secure Script Execution Environment

This guide provides comprehensive information for system administrators managing the BIP-04 Secure Script Execution Environment.

## System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- **Python Version**: Python 3.8 or higher
- **Memory**: 512MB RAM minimum, 1GB recommended
- **Disk Space**: 500MB for installation, 1GB for logs and quarantine
- **CPU**: 1 CPU core minimum, 2+ cores recommended

### Recommended Requirements
- **Operating System**: Ubuntu 20.04+ or RHEL 8+
- **Python Version**: Python 3.9+
- **Memory**: 2GB RAM
- **Disk Space**: 2GB+ for production workloads
- **CPU**: 4+ CPU cores for concurrent script execution

## Installation

### Automated Installation

```bash
# Clone the repository
git clone https://github.com/cmmv-hive/cmmv-hive.git
cd cmmv-hive

# Run installation script
./scripts/setup.sh

# Install Python dependencies
pip install -r requirements-secure.txt
```

### Manual Installation

1. **Install system dependencies**:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev build-essential

# CentOS/RHEL
sudo yum install python3 python3-pip python3-devel gcc
```

2. **Install Python packages**:
```bash
pip3 install pyyaml psutil pathlib
```

3. **Deploy the secure environment**:
```bash
# Copy files to production directory
sudo mkdir -p /opt/cmmv-secure-scripts
sudo cp -r scripts/secure/* /opt/cmmv-secure-scripts/
sudo cp scripts/config/security_policy.yml /opt/cmmv-secure-scripts/

# Set permissions
sudo chown -R cmmv-user:cmmv-group /opt/cmmv-secure-scripts
sudo chmod 755 /opt/cmmv-secure-scripts
```

## Configuration

### Security Policy Configuration

Edit `/opt/cmmv-secure-scripts/security_policy.yml`:

```yaml
security:
  execution:
    timeout_seconds: 300      # Maximum script execution time
    cpu_seconds: 60           # CPU time limit per script
    memory_mb: 512            # Memory limit per script
    file_size_mb: 100         # Maximum file size for creation
    max_processes: 5          # Maximum child processes per script

  filesystem:
    allowed_paths:            # Whitelisted directories
      - "/tmp"
      - "/var/log/cmmv"
      - "/opt/cmmv-secure-scripts/data"
    blocked_operations:       # Prohibited file operations
      - "delete"
      - "chmod"
      - "chown"

  network:
    allowed_domains:          # Allowed network domains
      - "api.cmmv-hive.org"
      - "registry.cmmv-hive.org"
    blocked_ports: [22, 23, 3389]  # Blocked network ports

  monitoring:
    log_level: "INFO"         # Logging level (DEBUG, INFO, WARNING, ERROR)
    alert_thresholds:         # Alert thresholds
      cpu_usage: 80           # CPU usage percentage
      memory_usage: 90        # Memory usage percentage
      execution_time: 250     # Execution time in seconds
```

### Production Configuration

Create `/opt/cmmv-secure-scripts/production_config.yml`:

```yaml
environment: production
log_level: WARNING
audit_retention_days: 90
alert_email: security@cmmv-hive.org
max_concurrent_scripts: 10
database_url: postgresql://user:pass@localhost/cmmv_secure
redis_url: redis://localhost:6379
```

## System Integration

### Environment Setup

1. **Add to system PATH**:
```bash
# Add to /etc/profile.d/cmmv-secure.sh
export PATH="$PATH:/opt/cmmv-secure-scripts"
export PYTHONPATH="$PYTHONPATH:/opt/cmmv-secure-scripts"
```

2. **Create system user**:
```bash
sudo useradd -r -s /bin/false cmmv-secure
sudo usermod -a -G cmmv-secure cmmv-secure
```

3. **Configure systemd service** (optional):
```ini
# /etc/systemd/system/cmmv-secure.service
[Unit]
Description=CMMV-Hive Secure Script Execution
After=network.target

[Service]
Type=simple
User=cmmv-secure
Group=cmmv-secure
ExecStart=/opt/cmmv-secure-scripts/monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Log Rotation

Configure logrotate for audit logs:

```bash
# /etc/logrotate.d/cmmv-secure
/opt/cmmv-secure-scripts/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 cmmv-secure cmmv-secure
    postrotate
        systemctl reload cmmv-secure.service
    endscript
}
```

## Monitoring and Alerting

### Real-time Monitoring

```bash
# Check system status
/opt/cmmv-secure-scripts/monitor_status.py

# View recent alerts
/opt/cmmv-secure-scripts/view_alerts.py --limit 10

# Monitor resource usage
/opt/cmmv-secure-scripts/resource_monitor.py
```

### Alert Configuration

Configure email alerts in `/opt/cmmv-secure-scripts/alert_config.yml`:

```yaml
alerts:
  email:
    enabled: true
    smtp_server: smtp.cmmv-hive.org
    smtp_port: 587
    username: alerts@cmmv-hive.org
    password: "${ALERT_PASSWORD}"
    recipients:
      - security@cmmv-hive.org
      - admin@cmmv-hive.org

  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"

  pagerduty:
    enabled: false
    service_key: "${PAGERDUTY_KEY}"
```

### Log Analysis

```bash
# Search for security events
grep "SECURITY_VIOLATION" /opt/cmmv-secure-scripts/logs/security_events.log

# Analyze execution patterns
/opt/cmmv-secure-scripts/analyze_logs.py --days 7

# Generate security reports
/opt/cmmv-secure-scripts/security_report.py --format pdf
```

## Security Management

### User Access Control

1. **Create execution users**:
```bash
sudo useradd -m script-user-1
sudo usermod -a -G cmmv-secure script-user-1
```

2. **Configure sudo access** (if needed):
```bash
# /etc/sudoers.d/cmmv-secure
script-user-1 ALL=(cmmv-secure) NOPASSWD: /opt/cmmv-secure-scripts/execute_script.py
```

3. **Set resource limits**:
```bash
# /etc/security/limits.d/cmmv-secure.conf
cmmv-secure soft nproc 50
cmmv-secure hard nproc 100
cmmv-secure soft nofile 1024
cmmv-secure hard nofile 2048
```

### Certificate Management

For secure communication:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout /opt/cmmv-secure-scripts/ssl/private.key \
  -out /opt/cmmv-secure-scripts/ssl/certificate.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=CMMV-Hive/CN=secure.cmmv-hive.org"

# Set permissions
chmod 600 /opt/cmmv-secure-scripts/ssl/private.key
chmod 644 /opt/cmmv-secure-scripts/ssl/certificate.crt
```

## Backup and Recovery

### Backup Configuration

```bash
# Create backup script
cat > /opt/cmmv-secure-scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/cmmv-secure-backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz \
  /opt/cmmv-secure-scripts/*.yml \
  /opt/cmmv-secure-scripts/*.yaml

# Backup logs (last 30 days)
find /opt/cmmv-secure-scripts/logs/ -name "*.log" -mtime -30 \
  -exec tar -rf $BACKUP_DIR/logs_$DATE.tar {} \;
gzip $BACKUP_DIR/logs_$DATE.tar

# Cleanup old backups (keep last 7)
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/cmmv-secure-scripts/backup.sh
```

### Recovery Procedures

1. **Configuration Recovery**:
```bash
# Restore configuration
sudo tar -xzf /opt/cmmv-secure-backups/config_20231201_120000.tar.gz \
  -C /opt/cmmv-secure-scripts/
```

2. **Full System Recovery**:
```bash
# Stop services
sudo systemctl stop cmmv-secure

# Restore from backup
sudo cp -r /opt/cmmv-secure-backups/full_backup/* /opt/cmmv-secure-scripts/

# Restart services
sudo systemctl start cmmv-secure
```

## Performance Tuning

### Resource Optimization

1. **Memory Management**:
```yaml
# Adjust memory limits based on workload
execution:
  memory_mb: 1024  # Increase for memory-intensive scripts
```

2. **CPU Optimization**:
```yaml
execution:
  cpu_seconds: 120  # Increase for CPU-intensive scripts
  max_processes: 8   # Adjust based on system capacity
```

3. **I/O Optimization**:
```yaml
filesystem:
  file_size_mb: 500  # Increase for large file operations
```

### Monitoring Performance

```bash
# Monitor system performance
vmstat 1 10
iostat -x 1 10
free -h

# Check script execution performance
/opt/cmmv-secure-scripts/performance_report.py
```

## Troubleshooting

### Common Issues

#### High Resource Usage
```bash
# Check running processes
ps aux | grep python

# Monitor resource usage
top -p $(pgrep -f "secure.*executor")

# Check logs for resource violations
grep "RESOURCE_LIMIT" /opt/cmmv-secure-scripts/logs/security_events.log
```

#### Script Execution Failures
```bash
# Check execution logs
tail -50 /opt/cmmv-secure-scripts/logs/execution_audit.log

# Validate script syntax
python3 -m py_compile /path/to/failing/script.py

# Check security policy violations
grep "POLICY_VIOLATION" /opt/cmmv-secure-scripts/logs/security_events.log
```

#### Network Issues
```bash
# Check network connectivity
curl -I https://api.cmmv-hive.org

# Verify DNS resolution
nslookup api.cmmv-hive.org

# Check firewall rules
sudo iptables -L
sudo ufw status
```

### Log Analysis

```bash
# Find error patterns
grep "ERROR\|FAILED" /opt/cmmv-secure-scripts/logs/*.log | tail -20

# Analyze execution times
awk '/execution_time/ {sum+=$2; count++} END {print "Average:", sum/count}' \
  /opt/cmmv-secure-scripts/logs/execution_audit.log

# Check security violations by type
grep "SECURITY_VIOLATION" /opt/cmmv-secure-scripts/logs/security_events.log | \
  awk '{print $4}' | sort | uniq -c | sort -nr
```

## Maintenance Tasks

### Daily Tasks
- Monitor system resources
- Review security alerts
- Check log file sizes
- Verify service status

### Weekly Tasks
- Review execution patterns
- Analyze security reports
- Update security policies
- Clean up old log files

### Monthly Tasks
- Security policy review
- Performance optimization
- Backup verification
- System updates

### Quarterly Tasks
- Comprehensive security audit
- Penetration testing
- Disaster recovery testing
- Documentation updates

## Security Auditing

### Regular Audits

1. **Configuration Audit**:
```bash
# Audit security policy
/opt/cmmv-secure-scripts/audit_policy.py

# Check file permissions
find /opt/cmmv-secure-scripts -type f -exec ls -l {} \; | grep -v "\-r\-\-\-\-\-\-\-"
```

2. **Log Analysis**:
```bash
# Analyze security events
/opt/cmmv-secure-scripts/audit_logs.py --period 30d

# Check for anomalies
/opt/cmmv-secure-scripts/anomaly_detection.py
```

3. **Access Review**:
```bash
# Review user access
/opt/cmmv-secure-scripts/access_review.py

# Check for unauthorized changes
/opt/cmmv-secure-scripts/integrity_check.py
```

## Compliance

### Regulatory Compliance

1. **Data Protection**:
   - Implement encryption for sensitive data
   - Regular data purging according to retention policies
   - Access logging for audit trails

2. **Security Standards**:
   - Follow OWASP security guidelines
   - Implement secure coding practices
   - Regular vulnerability assessments

### Documentation

Maintain comprehensive documentation:
- System architecture diagrams
- Security policy documentation
- Incident response procedures
- Change management records

## Support and Resources

### Getting Help

1. **Internal Resources**:
   - Development team documentation
   - Internal wiki and knowledge base
   - Team communication channels

2. **External Resources**:
   - Python security documentation
   - Linux security best practices
   - OWASP security guidelines

3. **Vendor Support**:
   - Python security libraries documentation
   - System administration resources
   - Security research publications

### Escalation Procedures

1. **Minor Issues**: Log and monitor
2. **Moderate Issues**: Investigate and document
3. **Critical Issues**: Immediate response and notification
4. **Security Incidents**: Follow incident response plan

---

This guide should be reviewed and updated quarterly to reflect system changes and new security requirements.
