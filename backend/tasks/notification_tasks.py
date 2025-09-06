#!/usr/bin/env python3
"""
Celery tasks for notifications and alerts.
"""
from celery import current_app
from services.celery_service import celery_app
from database.db import get_db
from datetime import datetime, timedelta
from flask_mail import Message
import logging
import json

logger = logging.getLogger(__name__)

@celery_app.task
def send_vulnerability_alert(scan_id, vulnerability_data):
    """
    Send immediate alert for high-severity vulnerabilities.
    
    Args:
        scan_id: Scan identifier
        vulnerability_data: Vulnerability details
        
    Returns:
        dict: Alert sending results
    """
    try:
        logger.info(f"Sending vulnerability alert for scan {scan_id}")
        
        from app import mail
        
        db = get_db()
        
        # Get scan data
        scan = db.scans.find_one({"_id": scan_id})
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Get notification settings
        notification_settings = db.settings.find_one({"type": "notifications"}) or {}
        alert_emails = notification_settings.get("alert_emails", [])
        
        if not alert_emails:
            logger.warning("No alert email addresses configured")
            return {"status": "skipped", "reason": "No recipients configured"}
        
        # Determine if alert should be sent based on severity
        severity = vulnerability_data.get("severity", "low")
        if severity not in ["high", "critical"]:
            logger.info(f"Skipping alert for {severity} severity vulnerability")
            return {"status": "skipped", "reason": f"Severity {severity} below alert threshold"}
        
        # Create alert email
        subject = f"🚨 HIGH SEVERITY VULNERABILITY DETECTED - {scan.get('target', 'Unknown Target')}"
        
        body = f"""
        SECURITY ALERT - IMMEDIATE ACTION REQUIRED
        
        A high-severity vulnerability has been detected during the security scan:
        
        VULNERABILITY DETAILS:
        - Title: {vulnerability_data.get('title', 'Unknown')}
        - Severity: {vulnerability_data.get('severity', 'Unknown').upper()}
        - Target: {scan.get('target', 'Unknown')}
        - Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        DESCRIPTION:
        {vulnerability_data.get('description', 'No description available')}
        
        AFFECTED SYSTEM:
        - Host: {vulnerability_data.get('host', 'N/A')}
        - Port: {vulnerability_data.get('port', 'N/A')}
        - Service: {vulnerability_data.get('service', 'N/A')}
        
        RECOMMENDED ACTIONS:
        1. Immediately assess the affected system
        2. Apply security patches if available
        3. Consider isolating the affected system if necessary
        4. Review the full scan report for additional details
        
        This is an automated alert from InfoSentinel Security Platform.
        Please do not reply to this email.
        
        Scan ID: {scan_id}
        Alert Generated: {datetime.utcnow().isoformat()}
        """
        
        # Send to all configured alert recipients
        alerts_sent = 0
        for email in alert_emails:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email],
                    body=body
                )
                
                mail.send(msg)
                alerts_sent += 1
                logger.info(f"Vulnerability alert sent to {email}")
                
            except Exception as e:
                logger.error(f"Failed to send alert to {email}: {str(e)}")
        
        # Log the alert
        alert_record = {
            "type": "vulnerability_alert",
            "scan_id": scan_id,
            "vulnerability_id": vulnerability_data.get("_id"),
            "severity": severity,
            "recipients": alert_emails,
            "alerts_sent": alerts_sent,
            "created_at": datetime.utcnow()
        }
        
        db.alerts.insert_one(alert_record)
        
        logger.info(f"Vulnerability alert completed: {alerts_sent} emails sent")
        
        return {
            "status": "sent",
            "alerts_sent": alerts_sent,
            "recipients": alert_emails
        }
        
    except Exception as e:
        logger.error(f"Error sending vulnerability alert for scan {scan_id}: {str(e)}")
        raise

@celery_app.task
def send_scan_completion_notification(scan_id):
    """
    Send notification when scan completes.
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        dict: Notification results
    """
    try:
        logger.info(f"Sending scan completion notification for {scan_id}")
        
        from app import mail
        
        db = get_db()
        
        # Get scan data
        scan = db.scans.find_one({"_id": scan_id})
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Get notification settings
        notification_settings = db.settings.find_one({"type": "notifications"}) or {}
        notification_emails = notification_settings.get("completion_emails", [])
        
        if not notification_emails:
            logger.info("No completion notification emails configured")
            return {"status": "skipped", "reason": "No recipients configured"}
        
        # Get vulnerability summary
        vulnerabilities = list(db.vulnerabilities.find({"scan_id": scan_id}))
        
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        medium_vulns = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
        low_vulns = len([v for v in vulnerabilities if v.get('severity') == 'low'])
        
        # Calculate scan duration
        start_time = scan.get('start_time')
        end_time = scan.get('end_time')
        duration = "Unknown"
        
        if start_time and end_time:
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            duration_delta = end_time - start_time
            duration = str(duration_delta).split('.')[0]  # Remove microseconds
        
        # Create notification email
        subject = f"✅ Security Scan Completed - {scan.get('target', 'Unknown Target')}"
        
        body = f"""
        Security Scan Completion Report
        
        Your security scan has been completed successfully.
        
        SCAN SUMMARY:
        - Target: {scan.get('target', 'Unknown')}
        - Scan Type: {scan.get('scan_type', 'Unknown')}
        - Status: {scan.get('status', 'Unknown')}
        - Duration: {duration}
        - Completed: {scan.get('end_time', 'Unknown')}
        
        VULNERABILITY SUMMARY:
        - Total Vulnerabilities: {len(vulnerabilities)}
        - High Severity: {high_vulns}
        - Medium Severity: {medium_vulns}
        - Low Severity: {low_vulns}
        
        NEXT STEPS:
        {'• Review high-severity vulnerabilities immediately' if high_vulns > 0 else ''}
        {'• Plan remediation for medium-severity issues' if medium_vulns > 0 else ''}
        • Access the full report in the InfoSentinel dashboard
        • Schedule follow-up scans as needed
        
        You can view the detailed results and download reports from the InfoSentinel platform.
        
        Scan ID: {scan_id}
        Notification Generated: {datetime.utcnow().isoformat()}
        
        ---
        InfoSentinel Security Platform
        """
        
        # Send notifications
        notifications_sent = 0
        for email in notification_emails:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email],
                    body=body
                )
                
                mail.send(msg)
                notifications_sent += 1
                logger.info(f"Completion notification sent to {email}")
                
            except Exception as e:
                logger.error(f"Failed to send notification to {email}: {str(e)}")
        
        # Log the notification
        notification_record = {
            "type": "scan_completion",
            "scan_id": scan_id,
            "recipients": notification_emails,
            "notifications_sent": notifications_sent,
            "vulnerability_summary": {
                "total": len(vulnerabilities),
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns
            },
            "created_at": datetime.utcnow()
        }
        
        db.notifications.insert_one(notification_record)
        
        logger.info(f"Scan completion notification completed: {notifications_sent} emails sent")
        
        return {
            "status": "sent",
            "notifications_sent": notifications_sent,
            "recipients": notification_emails
        }
        
    except Exception as e:
        logger.error(f"Error sending scan completion notification for {scan_id}: {str(e)}")
        raise

@celery_app.task
def send_daily_security_digest():
    """
    Send daily digest of security activities.
    
    Returns:
        dict: Digest sending results
    """
    try:
        logger.info("Generating daily security digest")
        
        from app import mail
        
        db = get_db()
        
        # Get notification settings
        notification_settings = db.settings.find_one({"type": "notifications"}) or {}
        digest_emails = notification_settings.get("digest_emails", [])
        
        if not digest_emails:
            logger.info("No digest email addresses configured")
            return {"status": "skipped", "reason": "No recipients configured"}
        
        # Get yesterday's data
        yesterday = datetime.utcnow() - timedelta(days=1)
        today = datetime.utcnow()
        
        # Get scans from last 24 hours
        recent_scans = list(db.scans.find({
            "start_time": {"$gte": yesterday, "$lt": today}
        }))
        
        # Get vulnerabilities from last 24 hours
        recent_vulnerabilities = list(db.vulnerabilities.find({
            "created_at": {"$gte": yesterday, "$lt": today}
        }))
        
        # Calculate statistics
        completed_scans = len([s for s in recent_scans if s.get('status') == 'completed'])
        failed_scans = len([s for s in recent_scans if s.get('status') == 'failed'])
        running_scans = len([s for s in recent_scans if s.get('status') == 'running'])
        
        high_vulns = len([v for v in recent_vulnerabilities if v.get('severity') == 'high'])
        medium_vulns = len([v for v in recent_vulnerabilities if v.get('severity') == 'medium'])
        low_vulns = len([v for v in recent_vulnerabilities if v.get('severity') == 'low'])
        
        # Create digest email
        subject = f"📊 InfoSentinel Daily Security Digest - {yesterday.strftime('%Y-%m-%d')}"
        
        body = f"""
        Daily Security Activity Digest
        Report Period: {yesterday.strftime('%Y-%m-%d')} to {today.strftime('%Y-%m-%d')}
        
        SCAN ACTIVITY SUMMARY:
        - Total Scans Initiated: {len(recent_scans)}
        - Completed Successfully: {completed_scans}
        - Failed Scans: {failed_scans}
        - Currently Running: {running_scans}
        
        VULNERABILITY DISCOVERY:
        - Total New Vulnerabilities: {len(recent_vulnerabilities)}
        - High Severity: {high_vulns}
        - Medium Severity: {medium_vulns}
        - Low Severity: {low_vulns}
        
        TOP TARGETS SCANNED:
        """
        
        # Add top targets
        target_counts = {}
        for scan in recent_scans:
            target = scan.get('target', 'Unknown')
            target_counts[target] = target_counts.get(target, 0) + 1
        
        sorted_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        for target, count in sorted_targets:
            body += f"        - {target}: {count} scan(s)\n"
        
        body += f"""
        
        SECURITY RECOMMENDATIONS:
        {'• Immediate attention required for high-severity vulnerabilities' if high_vulns > 0 else ''}
        {'• Review and plan remediation for medium-severity issues' if medium_vulns > 0 else ''}
        {'• Investigate failed scans and retry if necessary' if failed_scans > 0 else ''}
        • Continue regular security assessments
        • Review security policies and procedures
        
        ACCESS YOUR DASHBOARD:
        Log in to the InfoSentinel platform to view detailed reports and manage your security posture.
        
        Digest Generated: {datetime.utcnow().isoformat()}
        
        ---
        InfoSentinel Security Platform
        Automated Daily Digest
        """
        
        # Send digest emails
        digests_sent = 0
        for email in digest_emails:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email],
                    body=body
                )
                
                mail.send(msg)
                digests_sent += 1
                logger.info(f"Daily digest sent to {email}")
                
            except Exception as e:
                logger.error(f"Failed to send digest to {email}: {str(e)}")
        
        # Log the digest
        digest_record = {
            "type": "daily_digest",
            "period_start": yesterday,
            "period_end": today,
            "recipients": digest_emails,
            "digests_sent": digests_sent,
            "statistics": {
                "scans": {
                    "total": len(recent_scans),
                    "completed": completed_scans,
                    "failed": failed_scans,
                    "running": running_scans
                },
                "vulnerabilities": {
                    "total": len(recent_vulnerabilities),
                    "high": high_vulns,
                    "medium": medium_vulns,
                    "low": low_vulns
                }
            },
            "created_at": datetime.utcnow()
        }
        
        db.digests.insert_one(digest_record)
        
        logger.info(f"Daily security digest completed: {digests_sent} emails sent")
        
        return {
            "status": "sent",
            "digests_sent": digests_sent,
            "recipients": digest_emails,
            "statistics": digest_record["statistics"]
        }
        
    except Exception as e:
        logger.error(f"Error sending daily security digest: {str(e)}")
        raise

@celery_app.task
def send_system_health_alert(alert_type, message, severity="medium"):
    """
    Send system health alerts to administrators.
    
    Args:
        alert_type: Type of alert (disk_space, memory, cpu, etc.)
        message: Alert message
        severity: Alert severity (low, medium, high, critical)
        
    Returns:
        dict: Alert results
    """
    try:
        logger.info(f"Sending system health alert: {alert_type}")
        
        from app import mail
        
        db = get_db()
        
        # Get admin notification settings
        notification_settings = db.settings.find_one({"type": "notifications"}) or {}
        admin_emails = notification_settings.get("admin_emails", [])
        
        if not admin_emails:
            logger.warning("No admin email addresses configured for system alerts")
            return {"status": "skipped", "reason": "No admin recipients configured"}
        
        # Create system alert email
        severity_emoji = {
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🚨",
            "critical": "🔥"
        }
        
        subject = f"{severity_emoji.get(severity, '⚠️')} InfoSentinel System Alert - {alert_type.title()}"
        
        body = f"""
        SYSTEM HEALTH ALERT
        
        Alert Type: {alert_type.upper()}
        Severity: {severity.upper()}
        Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        MESSAGE:
        {message}
        
        RECOMMENDED ACTIONS:
        • Check system resources and performance
        • Review system logs for additional details
        • Take corrective action if necessary
        • Monitor system status closely
        
        This is an automated system alert from InfoSentinel.
        Please investigate and take appropriate action.
        
        ---
        InfoSentinel Security Platform
        System Monitoring
        """
        
        # Send alerts to admins
        alerts_sent = 0
        for email in admin_emails:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email],
                    body=body
                )
                
                mail.send(msg)
                alerts_sent += 1
                logger.info(f"System health alert sent to {email}")
                
            except Exception as e:
                logger.error(f"Failed to send system alert to {email}: {str(e)}")
        
        # Log the system alert
        alert_record = {
            "type": "system_health",
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "recipients": admin_emails,
            "alerts_sent": alerts_sent,
            "created_at": datetime.utcnow()
        }
        
        db.system_alerts.insert_one(alert_record)
        
        logger.info(f"System health alert completed: {alerts_sent} emails sent")
        
        return {
            "status": "sent",
            "alerts_sent": alerts_sent,
            "recipients": admin_emails
        }
        
    except Exception as e:
        logger.error(f"Error sending system health alert: {str(e)}")
        raise

@celery_app.task
def cleanup_old_notifications():
    """
    Clean up old notification records.
    
    Returns:
        dict: Cleanup results
    """
    try:
        logger.info("Cleaning up old notifications")
        
        db = get_db()
        
        # Delete notifications older than 90 days
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        # Clean up different notification types
        collections_to_clean = ['alerts', 'notifications', 'digests', 'system_alerts']
        total_deleted = 0
        
        for collection_name in collections_to_clean:
            collection = db[collection_name]
            result = collection.delete_many({
                "created_at": {"$lt": cutoff_date}
            })
            
            deleted_count = result.deleted_count
            total_deleted += deleted_count
            
            logger.info(f"Deleted {deleted_count} old records from {collection_name}")
        
        logger.info(f"Notification cleanup completed: {total_deleted} total records deleted")
        
        return {
            "total_deleted": total_deleted,
            "cutoff_date": cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error during notification cleanup: {str(e)}")
        raise