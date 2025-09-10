#!/usr/bin/env python3
"""
Email Service Backend
Handles actual email sending for the cybersecurity dashboard
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import logging
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()

@dataclass
class EmailConfig:
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    use_tls: bool
    from_email: str
    to_emails: List[str]
    subject_prefix: str

@dataclass
class AlertData:
    alert_type: str
    title: str
    message: str
    severity: str
    timestamp: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    threat_indicators: Optional[List[str]] = None
    affected_systems: Optional[List[str]] = None
    system_metrics: Optional[Dict[str, Any]] = None

class EmailService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.alert_history = {}
        self.cooldown_period = 300  # 5 minutes default
        
    def send_email(self, config: EmailConfig, subject: str, body: str, priority: str = "normal") -> bool:
        """Send email using SMTP"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = config.from_email
            msg['To'] = ', '.join(config.to_emails)
            msg['Subject'] = f"{config.subject_prefix} {subject}"
            
            # Add priority headers
            if priority == "high":
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
                msg['Importance'] = 'High'
            
            # Create HTML and plain text versions
            text_body = body
            html_body = self.create_html_email(subject, body, priority)
            
            # Attach both versions
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Create SMTP connection
            if config.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(config.smtp_server, config.smtp_port)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP(config.smtp_server, config.smtp_port)
            
            # Login and send
            server.login(config.smtp_username, config.smtp_password)
            server.sendmail(config.from_email, config.to_emails, msg.as_string())
            server.quit()
            
            self.logger.info(f"Email sent successfully: {subject}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            self.logger.error(f"SMTP Authentication failed: {e}")
            return False
        except smtplib.SMTPConnectError as e:
            self.logger.error(f"SMTP Connection failed: {e}")
            return False
        except smtplib.SMTPException as e:
            self.logger.error(f"SMTP Error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Email sending failed: {e}")
            return False
    
    def create_html_email(self, subject: str, body: str, priority: str) -> str:
        """Create HTML formatted email"""
        priority_color = "#dc2626" if priority == "high" else "#2563eb"
        priority_bg = "#fef2f2" if priority == "high" else "#eff6ff"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{subject}</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: {priority_bg}; border-left: 4px solid {priority_color}; padding: 20px; margin-bottom: 20px;">
                <h1 style="color: {priority_color}; margin: 0 0 10px 0; font-size: 24px;">
                    🛡️ Cybersecurity Alert
                </h1>
                <p style="margin: 0; font-weight: bold; color: {priority_color};">
                    Priority: {priority.upper()}
                </p>
            </div>
            
            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h2 style="color: #1f2937; margin: 0 0 15px 0;">Alert Details</h2>
                <div style="background: white; padding: 15px; border-radius: 6px; font-family: monospace; white-space: pre-wrap; border: 1px solid #e5e7eb;">
{body}
                </div>
            </div>
            
            <div style="background: #1f2937; color: white; padding: 15px; border-radius: 8px; text-align: center;">
                <p style="margin: 0; font-size: 14px;">
                    🕒 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </p>
                <p style="margin: 5px 0 0 0; font-size: 12px; opacity: 0.8;">
                    Cybersecurity Operations Center - Automated Alert System
                </p>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background: #fef3c7; border-radius: 8px; border-left: 4px solid #f59e0b;">
                <h3 style="color: #92400e; margin: 0 0 10px 0; font-size: 16px;">⚠️ Important</h3>
                <ul style="margin: 0; padding-left: 20px; color: #92400e;">
                    <li>This is an automated security alert</li>
                    <li>Immediate investigation may be required</li>
                    <li>Do not ignore critical or high priority alerts</li>
                    <li>Contact your security team if unsure</li>
                </ul>
            </div>
        </body>
        </html>
        """
        return html
    
    def should_send_alert(self, alert_type: str, cooldown_period: int = None) -> bool:
        """Check if alert should be sent based on cooldown period"""
        cooldown = cooldown_period or self.cooldown_period
        now = datetime.now().timestamp()
        last_sent = self.alert_history.get(alert_type, 0)
        
        if now - last_sent > cooldown:
            self.alert_history[alert_type] = now
            return True
        return False
    
    def send_system_alert(self, config: EmailConfig, alert_data: AlertData) -> bool:
        """Send system resource alert"""
        if not self.should_send_alert(f"system_{alert_data.alert_type}"):
            self.logger.info(f"Alert {alert_data.alert_type} skipped due to cooldown")
            return True
        
        subject = f"System Alert - {alert_data.title}"
        
        body = f"""SYSTEM RESOURCE ALERT

Alert Type: {alert_data.alert_type.upper()}
Severity: {alert_data.severity.upper()}
Message: {alert_data.message}
Timestamp: {alert_data.timestamp}

"""
        
        if alert_data.system_metrics:
            body += "CURRENT SYSTEM STATUS:\n"
            for metric, value in alert_data.system_metrics.items():
                body += f"- {metric}: {value}\n"
            body += "\n"
        
        body += """RECOMMENDED ACTIONS:
- Check system performance immediately
- Investigate high resource usage
- Consider scaling resources if needed
- Monitor for continued issues

This alert was generated by the Cybersecurity Operations Center."""
        
        priority = "high" if alert_data.severity in ['critical', 'high'] else "normal"
        return self.send_email(config, subject, body, priority)
    
    def send_threat_alert(self, config: EmailConfig, alert_data: AlertData) -> bool:
        """Send cybersecurity threat alert"""
        if not self.should_send_alert(f"threat_{alert_data.alert_type}"):
            self.logger.info(f"Threat alert {alert_data.alert_type} skipped due to cooldown")
            return True
        
        subject = f"CYBERSECURITY THREAT - {alert_data.title}"
        
        body = f"""🚨 CYBERSECURITY THREAT DETECTED 🚨

Threat Type: {alert_data.alert_type.upper()}
Severity: {alert_data.severity.upper()}
Description: {alert_data.message}
Timestamp: {alert_data.timestamp}

"""
        
        if alert_data.source_ip:
            body += f"Source IP: {alert_data.source_ip}\n"
        if alert_data.destination_ip:
            body += f"Destination IP: {alert_data.destination_ip}\n"
        
        if alert_data.threat_indicators:
            body += "\nTHREAT INDICATORS:\n"
            for indicator in alert_data.threat_indicators:
                body += f"- {indicator}\n"
        
        if alert_data.affected_systems:
            body += "\nAFFECTED SYSTEMS:\n"
            for system in alert_data.affected_systems:
                body += f"- {system}\n"
        
        body += """
IMMEDIATE ACTIONS REQUIRED:
- Investigate the source IP immediately
- Check system logs for related activity
- Consider blocking the source if confirmed malicious
- Monitor for additional threats from this source
- Escalate to security team if severity is critical
- Document findings in the incident response system

This is an automated alert from the Advanced Threat Detection System.
Immediate response may be required to prevent security compromise."""
        
        return self.send_email(config, subject, body, "high")
    
    def send_incident_alert(self, config: EmailConfig, alert_data: AlertData) -> bool:
        """Send security incident alert"""
        if not self.should_send_alert(f"incident_{alert_data.alert_type}"):
            self.logger.info(f"Incident alert {alert_data.alert_type} skipped due to cooldown")
            return True
        
        subject = f"SECURITY INCIDENT - {alert_data.title}"
        
        body = f"""🔴 SECURITY INCIDENT DETECTED 🔴

Incident Type: {alert_data.alert_type.upper()}
Severity: {alert_data.severity.upper()}
Description: {alert_data.message}
Timestamp: {alert_data.timestamp}

"""
        
        if alert_data.source_ip:
            body += f"Source: {alert_data.source_ip}\n"
        if alert_data.destination_ip:
            body += f"Target: {alert_data.destination_ip}\n"
        
        if alert_data.affected_systems:
            body += "\nAFFECTED SYSTEMS:\n"
            for system in alert_data.affected_systems:
                body += f"- {system}\n"
        
        body += """
INCIDENT RESPONSE REQUIRED:
- Acknowledge this incident in the SOC dashboard
- Begin investigation immediately
- Isolate affected systems if necessary
- Collect forensic evidence
- Notify stakeholders as per incident response plan
- Update incident status as investigation progresses

This incident requires immediate attention from the security team."""
        
        priority = "high" if alert_data.severity in ['critical', 'high'] else "normal"
        return self.send_email(config, subject, body, priority)

# Flask app for email service
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

email_service = EmailService()

@app.route('/api/email/send', methods=['POST'])
def send_email():
    """Send email alert"""
    try:
        data = request.json
        
        # Extract configuration
        config_data = data.get('config', {})
        config = EmailConfig(
            smtp_server=config_data.get('smtpServer', ''),
            smtp_port=config_data.get('smtpPort', 587),
            smtp_username=config_data.get('smtpUsername', ''),
            smtp_password=config_data.get('smtpPassword', ''),
            use_tls=config_data.get('useTls', True),
            from_email=config_data.get('fromEmail', ''),
            to_emails=config_data.get('toEmails', []),
            subject_prefix=config_data.get('subjectPrefix', '[ALERT]')
        )
        
        # Validate configuration
        if not all([config.smtp_server, config.smtp_username, config.smtp_password, config.from_email]):
            return jsonify({'error': 'Missing required email configuration'}), 400
        
        if not config.to_emails:
            return jsonify({'error': 'No recipient emails specified'}), 400
        
        # Extract alert data
        alert_data = AlertData(
            alert_type=data.get('alertType', 'unknown'),
            title=data.get('title', 'Alert'),
            message=data.get('message', ''),
            severity=data.get('severity', 'medium'),
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            source_ip=data.get('sourceIp'),
            destination_ip=data.get('destinationIp'),
            threat_indicators=data.get('threatIndicators'),
            affected_systems=data.get('affectedSystems'),
            system_metrics=data.get('systemMetrics')
        )
        
        # Determine alert type and send appropriate email
        alert_category = data.get('category', 'system')
        
        if alert_category == 'threat':
            success = email_service.send_threat_alert(config, alert_data)
        elif alert_category == 'incident':
            success = email_service.send_incident_alert(config, alert_data)
        else:
            success = email_service.send_system_alert(config, alert_data)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Email sent successfully'})
        else:
            return jsonify({'error': 'Failed to send email'}), 500
            
    except Exception as e:
        logging.error(f"Email API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/test', methods=['POST'])
def test_email():
    """Send test email"""
    try:
        data = request.json
        config_data = data.get('config', {})
        
        config = EmailConfig(
            smtp_server=config_data.get('smtpServer', ''),
            smtp_port=config_data.get('smtpPort', 587),
            smtp_username=config_data.get('smtpUsername', ''),
            smtp_password=config_data.get('smtpPassword', ''),
            use_tls=config_data.get('useTls', True),
            from_email=config_data.get('fromEmail', ''),
            to_emails=config_data.get('toEmails', []),
            subject_prefix=config_data.get('subjectPrefix', '[TEST]')
        )
        
        # Create test alert
        test_alert = AlertData(
            alert_type='test',
            title='Email Configuration Test',
            message='This is a test email to verify your email configuration is working correctly.',
            severity='info',
            timestamp=datetime.now().isoformat(),
            system_metrics={
                'CPU Usage': '45%',
                'Memory Usage': '60%',
                'Disk Usage': '35%',
                'Network Status': 'Normal'
            }
        )
        
        success = email_service.send_system_alert(config, test_alert)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Test email sent successfully'})
        else:
            return jsonify({'error': 'Failed to send test email'}), 500
            
    except Exception as e:
        logging.error(f"Test email error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/health', methods=['GET'])
def health_check():
    """Health check for email service"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'email_backend'
    })

if __name__ == '__main__':
    print("📧 Email Service Backend")
    print("=" * 30)
    print("📤 SMTP email sending service")
    print("🔒 Secure email configuration")
    print("📊 Alert categorization and formatting")
    print("🌐 REST API for frontend integration")
    print()
    print("API Endpoints:")
    print("  POST /api/email/send - Send email alert")
    print("  POST /api/email/test - Send test email")
    print("  GET  /api/email/health - Health check")
    print()
    print("🚀 Starting email service on http://0.0.0.0:8004")
    print("   Make sure to configure SMTP settings in the frontend")
    print("   Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=8004, debug=False)