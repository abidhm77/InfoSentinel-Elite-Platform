"""Database service layer for InfoSentinel Enterprise Security Platform."""
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from database.models import (
    User, Scan, Vulnerability, ComplianceResult, SecurityEvent, 
    Notification, AuditLog, ScanQueue, db_config
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import uuid
import json

class DatabaseService:
    """Service layer for database operations."""
    
    def __init__(self):
        self.db_config = db_config
    
    def get_session(self) -> Session:
        """Get database session."""
        return self.db_config.get_session()
    
    # User Management
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict[str, Any]:
        """Create a new user."""
        session = self.get_session()
        try:
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                return {'success': False, 'message': 'User already exists'}
            
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role
            )
            
            session.add(user)
            session.commit()
            
            return {
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
            }
        except Exception as e:
            session.rollback()
            return {'success': False, 'message': str(e)}
        finally:
            session.close()
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user credentials."""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(username=username, is_active=True).first()
            
            if user and check_password_hash(user.password_hash, password):
                # Update last login
                user.last_login = datetime.utcnow()
                session.commit()
                
                return {
                    'success': True,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role
                    }
                }
            else:
                return {'success': False, 'message': 'Invalid credentials'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            session.close()
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(username=username, is_active=True).first()
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            return None
        except Exception as e:
            return None
        finally:
            session.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(id=user_id, is_active=True).first()
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            return None
        finally:
            session.close()
    
    # Scan Management
    def create_scan(self, user_id: int, target: str, scan_type: str, config: Dict = None) -> Dict[str, Any]:
        """Create a new scan."""
        session = self.get_session()
        try:
            scan_id = f"scan_{uuid.uuid4().hex[:8]}_{int(datetime.utcnow().timestamp())}"
            
            scan = Scan(
                id=scan_id,
                user_id=user_id,
                target=target,
                scan_type=scan_type,
                config=config or {},
                status='pending'
            )
            
            session.add(scan)
            session.commit()
            
            return {
                'success': True,
                'scan': {
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'progress': scan.progress,
                    'start_time': scan.start_time.isoformat() if scan.start_time else None
                }
            }
        except Exception as e:
            session.rollback()
            return {'success': False, 'message': str(e)}
        finally:
            session.close()
    
    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan by ID with vulnerabilities."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if not scan:
                return None
            
            vulnerabilities = session.query(Vulnerability).filter_by(scan_id=scan_id).all()
            
            return {
                'id': scan.id,
                'target': scan.target,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'progress': scan.progress,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'error_message': scan.error_message,
                'vulnerabilities': [
                    {
                        'id': vuln.id,
                        'title': vuln.title,
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'cve_id': vuln.cve_id,
                        'location': vuln.location,
                        'remediation': vuln.remediation,
                        'tool': vuln.tool,
                        'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None
                    }
                    for vuln in vulnerabilities
                ]
            }
        finally:
            session.close()
    
    def get_user_scans(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scans for a user."""
        session = self.get_session()
        try:
            scans = session.query(Scan).filter_by(user_id=user_id).order_by(
                desc(Scan.start_time)
            ).limit(limit).all()
            
            return [
                {
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'progress': scan.progress,
                    'start_time': scan.start_time.isoformat() if scan.start_time else None,
                    'end_time': scan.end_time.isoformat() if scan.end_time else None
                }
                for scan in scans
            ]
        except Exception as e:
            return []
        finally:
            session.close()
    
    # Admin Scan Management
    def get_all_scans_with_details(self) -> List[Dict[str, Any]]:
        """Get all scans with detailed information for admin dashboard."""
        session = self.get_session()
        try:
            scans = session.query(Scan).order_by(desc(Scan.start_time)).all()
            
            result = []
            for scan in scans:
                user = session.query(User).filter_by(id=scan.user_id).first()
                vulnerabilities = session.query(Vulnerability).filter_by(scan_id=scan.id).count()
                
                result.append({
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'progress': scan.progress,
                    'start_time': scan.start_time.isoformat() if scan.start_time else None,
                    'end_time': scan.end_time.isoformat() if scan.end_time else None,
                    'error_message': scan.error_message,
                    'user': user.username if user else 'Unknown',
                    'vulnerability_count': vulnerabilities,
                    'config': scan.config
                })
            
            return result
        finally:
            session.close()
    
    def get_scan_with_details(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific scan."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if not scan:
                return None
            
            user = session.query(User).filter_by(id=scan.user_id).first()
            vulnerabilities = session.query(Vulnerability).filter_by(scan_id=scan_id).all()
            
            return {
                'id': scan.id,
                'target': scan.target,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'progress': scan.progress,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'error_message': scan.error_message,
                'user': user.username if user else 'Unknown',
                'config': scan.config,
                'vulnerabilities': [
                    {
                        'id': vuln.id,
                        'title': vuln.title,
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'cve_id': vuln.cve_id,
                        'location': vuln.location,
                        'tool': vuln.tool
                    }
                    for vuln in vulnerabilities
                ]
            }
        finally:
            session.close()
    
    def get_scan_queue_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get queue status for a specific scan."""
        session = self.get_session()
        try:
            queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
            if not queue_entry:
                return None
            
            return {
                'status': queue_entry.status,
                'worker_id': queue_entry.worker_id,
                'started_at': queue_entry.started_at.isoformat() if queue_entry.started_at else None,
                'completed_at': queue_entry.completed_at.isoformat() if queue_entry.completed_at else None,
                'error_message': queue_entry.error_message,
                'retry_count': queue_entry.retry_count
            }
        finally:
            session.close()
    
    def pause_scan(self, scan_id: str) -> bool:
        """Pause an active scan."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan and scan.status == 'processing':
                scan.status = 'paused'
                session.commit()
                return True
            return False
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()
    
    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan and scan.status == 'paused':
                scan.status = 'processing'
                session.commit()
                return True
            return False
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop an active scan."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan and scan.status in ['processing', 'pending', 'paused']:
                scan.status = 'stopped'
                scan.end_time = datetime.utcnow()
                session.commit()
                
                # Update queue
                queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
                if queue_entry:
                    queue_entry.status = 'stopped'
                    queue_entry.completed_at = datetime.utcnow()
                    session.commit()
                
                return True
            return False
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()
    
    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get all active scans (pending or processing)."""
        session = self.get_session()
        try:
            scans = session.query(Scan).filter(
                Scan.status.in_(['pending', 'processing', 'paused'])
            ).order_by(desc(Scan.start_time)).all()
            
            return [
                {
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'progress': scan.progress,
                    'start_time': scan.start_time.isoformat() if scan.start_time else None,
                    'user': scan.user.username if scan.user else 'Unknown'
                }
                for scan in scans
            ]
        finally:
            session.close()
    
    def get_scan_logs(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get logs for a specific scan."""
        session = self.get_session()
        try:
            # For now, return basic scan info as logs
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if not scan:
                return []
            
            return [
                {
                    'timestamp': scan.start_time.isoformat() if scan.start_time else None,
                    'level': 'INFO',
                    'message': f"Scan {scan.id} started for target {scan.target}",
                    'component': 'scanner'
                }
            ]
        finally:
            session.close()
    
    def get_workers_status(self) -> List[Dict[str, Any]]:
        """Get status of scan workers."""
        # For now, return basic worker info
        return [
            {
                'id': 'worker-1',
                'status': 'active',
                'current_scan': None,
                'completed_scans': 0,
                'uptime': '2 hours'
            },
            {
                'id': 'worker-2',
                'status': 'active',
                'current_scan': None,
                'completed_scans': 0,
                'uptime': '2 hours'
            },
            {
                'id': 'worker-3',
                'status': 'active',
                'current_scan': None,
                'completed_scans': 5,
                'uptime': '2 hours'
            }
        ]
    
    def update_scan_status(self, scan_id: str, status: str, progress: int = None, 
                          error_message: str = None) -> bool:
        """Update scan status and progress."""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if not scan:
                return False
            
            scan.status = status
            if progress is not None:
                scan.progress = progress
            if error_message:
                scan.error_message = error_message
            if status == 'completed':
                scan.end_time = datetime.utcnow()
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
    
    # Vulnerability Management
    def add_vulnerability(self, scan_id: str, title: str, description: str, 
                         severity: str, **kwargs) -> bool:
        """Add vulnerability to scan."""
        session = self.get_session()
        try:
            vulnerability = Vulnerability(
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=kwargs.get('cvss_score'),
                cve_id=kwargs.get('cve_id'),
                location=kwargs.get('location'),
                remediation=kwargs.get('remediation'),
                tool=kwargs.get('tool'),
                raw_output=kwargs.get('raw_output')
            )
            
            session.add(vulnerability)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
    
    # Security Events
    def create_security_event(self, event_type: str, severity: str, source: str, 
                            target: str, description: str, details: Dict = None, 
                            threat_score: float = 0.0) -> str:
        """Create security event."""
        session = self.get_session()
        try:
            event_id = f"evt_{uuid.uuid4().hex[:8]}_{int(datetime.utcnow().timestamp())}"
            
            event = SecurityEvent(
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                source=source,
                target=target,
                description=description,
                details=details or {},
                threat_score=threat_score
            )
            
            session.add(event)
            session.commit()
            return event_id
        except Exception as e:
            session.rollback()
            return None
        finally:
            session.close()
    
    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events."""
        session = self.get_session()
        try:
            events = session.query(SecurityEvent).order_by(
                desc(SecurityEvent.timestamp)
            ).limit(limit).all()
            
            return [
                {
                    'id': event.id,
                    'event_id': event.event_id,
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'source': event.source,
                    'target': event.target,
                    'description': event.description,
                    'details': event.details,
                    'threat_score': event.threat_score,
                    'status': event.status,
                    'timestamp': event.timestamp.isoformat() if event.timestamp else None
                }
                for event in events
            ]
        finally:
            session.close()
    
    # Notifications
    def create_notification(self, user_id: int, title: str, message: str, 
                          notification_type: str = 'info') -> bool:
        """Create notification for user."""
        session = self.get_session()
        try:
            notification = Notification(
                user_id=user_id,
                title=title,
                message=message,
                type=notification_type
            )
            
            session.add(notification)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
    
    def get_user_notifications(self, user_id: int, unread_only: bool = False) -> List[Dict[str, Any]]:
        """Get notifications for user."""
        session = self.get_session()
        try:
            query = session.query(Notification).filter_by(user_id=user_id)
            if unread_only:
                query = query.filter_by(read=False)
            
            notifications = query.order_by(desc(Notification.created_at)).all()
            
            return [
                {
                    'id': notif.id,
                    'title': notif.title,
                    'message': notif.message,
                    'type': notif.type,
                    'read': notif.read,
                    'created_at': notif.created_at.isoformat() if notif.created_at else None
                }
                for notif in notifications
            ]
        finally:
            session.close()
    
    def mark_notification_read(self, notification_id: int, user_id: int) -> bool:
        """Mark notification as read."""
        session = self.get_session()
        try:
            notification = session.query(Notification).filter_by(
                id=notification_id, user_id=user_id
            ).first()
            
            if notification:
                notification.read = True
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
    
    # Dashboard Statistics
    def get_dashboard_stats(self, user_id: int = None) -> Dict[str, Any]:
        """Get dashboard statistics."""
        session = self.get_session()
        try:
            # Base queries
            scan_query = session.query(Scan)
            vuln_query = session.query(Vulnerability)
            event_query = session.query(SecurityEvent)
            
            if user_id:
                scan_query = scan_query.filter_by(user_id=user_id)
                vuln_query = vuln_query.join(Scan).filter(Scan.user_id == user_id)
            
            # Scan statistics
            total_scans = scan_query.count()
            running_scans = scan_query.filter_by(status='running').count()
            completed_scans = scan_query.filter_by(status='completed').count()
            failed_scans = scan_query.filter_by(status='failed').count()
            
            # Vulnerability statistics
            total_vulns = vuln_query.count()
            critical_vulns = vuln_query.filter_by(severity='critical').count()
            high_vulns = vuln_query.filter_by(severity='high').count()
            medium_vulns = vuln_query.filter_by(severity='medium').count()
            low_vulns = vuln_query.filter_by(severity='low').count()
            
            # Security events (last 24 hours)
            yesterday = datetime.utcnow() - timedelta(days=1)
            recent_events = event_query.filter(SecurityEvent.timestamp >= yesterday).count()
            
            return {
                'scans': {
                    'total': total_scans,
                    'running': running_scans,
                    'completed': completed_scans,
                    'failed': failed_scans
                },
                'vulnerabilities': {
                    'total': total_vulns,
                    'critical': critical_vulns,
                    'high': high_vulns,
                    'medium': medium_vulns,
                    'low': low_vulns
                },
                'security_events': {
                    'last_24h': recent_events
                }
            }
        finally:
            session.close()
    
    # Audit Logging
    def log_action(self, user_id: int, action: str, resource: str = None, 
                  resource_id: str = None, details: Dict = None, 
                  ip_address: str = None, user_agent: str = None) -> bool:
        """Log user action for audit trail."""
        session = self.get_session()
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                resource_id=resource_id,
                details=details or {},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            session.add(audit_log)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()

# Global database service instance
db_service = DatabaseService()