"""Scan queue management system for InfoSentinel Enterprise."""
import threading
import queue
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict
from services.database_service import db_service
from services.enterprise_logger import log_info, log_error, log_warning

class ScanPriority(Enum):
    """Scan priority levels."""
    LOW = 1
    NORMAL = 5
    HIGH = 8
    CRITICAL = 10

class ScanStatus(Enum):
    """Scan status enumeration."""
    QUEUED = 'queued'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    RETRYING = 'retrying'

@dataclass
class ScanJob:
    """Scan job data structure."""
    scan_id: str
    user_id: int
    target: str
    scan_type: str
    config: Dict[str, Any]
    priority: ScanPriority
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int = 3600  # 1 hour default
    worker_id: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['priority'] = self.priority.value
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['scheduled_at'] = self.scheduled_at.isoformat() if self.scheduled_at else None
        data['started_at'] = self.started_at.isoformat() if self.started_at else None
        data['completed_at'] = self.completed_at.isoformat() if self.completed_at else None
        return data

class ScanWorker(threading.Thread):
    """Background worker for processing scan jobs."""
    
    def __init__(self, worker_id: str, queue_manager: 'ScanQueueManager'):
        super().__init__()
        self.worker_id = worker_id
        self.queue_manager = queue_manager
        self.daemon = True
        self.running = True
        self.current_job: Optional[ScanJob] = None
        
    def run(self):
        """Main worker loop."""
        log_info(f"Scan worker {self.worker_id} started")
        
        while self.running:
            try:
                # Get next job from queue
                job = self.queue_manager.get_next_job()
                
                if job is None:
                    time.sleep(1)  # No jobs available, wait
                    continue
                
                self.current_job = job
                self.process_job(job)
                
            except Exception as e:
                log_error(f"Worker {self.worker_id} error", error=e)
                if self.current_job:
                    self.queue_manager.mark_job_failed(
                        self.current_job.scan_id, 
                        f"Worker error: {str(e)}"
                    )
                time.sleep(5)  # Wait before retrying
            
            finally:
                self.current_job = None
    
    def process_job(self, job: ScanJob):
        """Process a single scan job."""
        try:
            log_info(f"Worker {self.worker_id} processing scan {job.scan_id}")
            
            # Mark job as processing
            self.queue_manager.mark_job_processing(job.scan_id, self.worker_id)
            
            # Update scan status in database
            db_service.update_scan_status(job.scan_id, 'running', 5)
            
            # Execute the actual scan based on type
            if job.scan_type == 'web':
                self._execute_web_scan(job)
            elif job.scan_type == 'network':
                self._execute_network_scan(job)
            elif job.scan_type == 'comprehensive':
                self._execute_comprehensive_scan(job)
            else:
                self._execute_basic_scan(job)
            
            # Mark job as completed
            self.queue_manager.mark_job_completed(job.scan_id)
            log_info(f"Worker {self.worker_id} completed scan {job.scan_id}")
            
        except Exception as e:
            log_error(f"Error processing scan {job.scan_id}", error=e)
            self.queue_manager.mark_job_failed(job.scan_id, str(e))
    
    def _execute_web_scan(self, job: ScanJob):
        """Execute web application scan."""
        from scanners.web_app_scanner import WebAppScanner
        scanner = WebAppScanner()
        scanner._run_comprehensive_scan(job.scan_id, job.target, job.config)
    
    def _execute_network_scan(self, job: ScanJob):
        """Execute network scan."""
        from scanners.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        scanner.start_scan(job.scan_id, job.target, job.config)
    
    def _execute_comprehensive_scan(self, job: ScanJob):
        """Execute comprehensive scan."""
        # Run both web and network scans
        try:
            db_service.update_scan_status(job.scan_id, 'running', 20)
            self._execute_network_scan(job)
            
            db_service.update_scan_status(job.scan_id, 'running', 60)
            self._execute_web_scan(job)
            
            db_service.update_scan_status(job.scan_id, 'completed', 100)
        except Exception as e:
            db_service.update_scan_status(job.scan_id, 'failed', error_message=str(e))
            raise
    
    def _execute_basic_scan(self, job: ScanJob):
        """Execute basic scan with fallback tools."""
        import subprocess
        import requests
        
        try:
            db_service.update_scan_status(job.scan_id, 'running', 30)
            
            # Basic port scan
            try:
                result = subprocess.run(
                    ['nmap', '-sS', '-O', job.target],
                    capture_output=True, text=True, timeout=300
                )
                
                if result.returncode == 0:
                    # Parse and store results
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'open' in line.lower():
                            db_service.add_vulnerability(
                                scan_id=job.scan_id,
                                title='Open Port Detected',
                                description=line.strip(),
                                severity='low',
                                tool='nmap'
                            )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                log_warning(f"Nmap not available for scan {job.scan_id}")
            
            db_service.update_scan_status(job.scan_id, 'running', 70)
            
            # Basic web check
            if not job.target.replace('.', '').isdigit():  # Not an IP address
                try:
                    test_url = job.target if job.target.startswith('http') else f'http://{job.target}'
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for basic security headers
                    if 'X-Frame-Options' not in response.headers:
                        db_service.add_vulnerability(
                            scan_id=job.scan_id,
                            title='Missing X-Frame-Options Header',
                            description='The X-Frame-Options security header is missing',
                            severity='medium',
                            location='HTTP Headers',
                            tool='basic_scanner'
                        )
                except:
                    pass
            
            db_service.update_scan_status(job.scan_id, 'completed', 100)
            
        except Exception as e:
            db_service.update_scan_status(job.scan_id, 'failed', error_message=str(e))
            raise
    
    def stop(self):
        """Stop the worker."""
        self.running = False
        log_info(f"Scan worker {self.worker_id} stopped")

class ScanQueueManager:
    """Manages scan job queue and worker processes."""
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.job_queue = queue.PriorityQueue()
        self.workers: List[ScanWorker] = []
        self.jobs: Dict[str, ScanJob] = {}
        self.running = False
        self.lock = threading.Lock()
        
    def start(self):
        """Start the queue manager and workers."""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.max_workers):
            worker = ScanWorker(f"worker-{i+1}", self)
            worker.start()
            self.workers.append(worker)
        
        log_info(f"Scan queue manager started with {self.max_workers} workers")
    
    def stop(self):
        """Stop the queue manager and all workers."""
        if not self.running:
            return
        
        self.running = False
        
        # Stop all workers
        for worker in self.workers:
            worker.stop()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
        log_info("Scan queue manager stopped")
    
    def add_scan_job(self, scan_id: str, user_id: int, target: str, 
                    scan_type: str, config: Dict[str, Any], 
                    priority: ScanPriority = ScanPriority.NORMAL,
                    scheduled_at: Optional[datetime] = None) -> bool:
        """Add a new scan job to the queue."""
        try:
            job = ScanJob(
                scan_id=scan_id,
                user_id=user_id,
                target=target,
                scan_type=scan_type,
                config=config,
                priority=priority,
                created_at=datetime.utcnow(),
                scheduled_at=scheduled_at
            )
            
            with self.lock:
                self.jobs[scan_id] = job
                
                # Add to priority queue (lower priority value = higher priority)
                priority_value = -priority.value  # Negative for reverse order
                self.job_queue.put((priority_value, time.time(), job))
            
            # Store in database
            try:
                session = db_service.get_session()
                from database.models import ScanQueue
                
                queue_entry = ScanQueue(
                    scan_id=scan_id,
                    priority=priority.value,
                    status='queued'
                )
                session.add(queue_entry)
                session.commit()
                session.close()
            except Exception as e:
                log_error("Failed to store scan job in database", error=e)
            
            log_info(f"Added scan job {scan_id} to queue with priority {priority.name}")
            return True
            
        except Exception as e:
            log_error(f"Failed to add scan job {scan_id}", error=e)
            return False
    
    def get_next_job(self) -> Optional[ScanJob]:
        """Get the next job from the queue."""
        try:
            # Check for scheduled jobs that are ready
            current_time = datetime.utcnow()
            
            while not self.job_queue.empty():
                priority_value, timestamp, job = self.job_queue.get_nowait()
                
                # Check if job is scheduled for later
                if job.scheduled_at and job.scheduled_at > current_time:
                    # Put it back in queue
                    self.job_queue.put((priority_value, timestamp, job))
                    time.sleep(1)
                    continue
                
                return job
            
            return None
            
        except queue.Empty:
            return None
        except Exception as e:
            log_error("Error getting next job from queue", error=e)
            return None
    
    def mark_job_processing(self, scan_id: str, worker_id: str):
        """Mark a job as being processed."""
        with self.lock:
            if scan_id in self.jobs:
                job = self.jobs[scan_id]
                job.started_at = datetime.utcnow()
                job.worker_id = worker_id
        
        # Update database
        try:
            session = db_service.get_session()
            from database.models import ScanQueue
            
            queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
            if queue_entry:
                queue_entry.status = 'processing'
                queue_entry.worker_id = worker_id
                queue_entry.started_at = datetime.utcnow()
                session.commit()
            session.close()
        except Exception as e:
            log_error("Failed to update scan job status in database", error=e)
    
    def mark_job_completed(self, scan_id: str):
        """Mark a job as completed."""
        with self.lock:
            if scan_id in self.jobs:
                job = self.jobs[scan_id]
                job.completed_at = datetime.utcnow()
                del self.jobs[scan_id]
        
        # Update database
        try:
            session = db_service.get_session()
            from database.models import ScanQueue
            
            queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
            if queue_entry:
                queue_entry.status = 'completed'
                queue_entry.completed_at = datetime.utcnow()
                session.commit()
            session.close()
        except Exception as e:
            log_error("Failed to update scan job completion in database", error=e)
    
    def mark_job_failed(self, scan_id: str, error_message: str):
        """Mark a job as failed."""
        with self.lock:
            if scan_id in self.jobs:
                job = self.jobs[scan_id]
                job.error_message = error_message
                job.retry_count += 1
                
                # Check if we should retry
                if job.retry_count < job.max_retries:
                    # Retry with lower priority
                    retry_priority = max(ScanPriority.LOW.value, job.priority.value - 1)
                    # Map integer to corresponding ScanPriority enum
                    if retry_priority <= ScanPriority.LOW.value:
                        job.priority = ScanPriority.LOW
                    elif retry_priority <= ScanPriority.NORMAL.value:
                        job.priority = ScanPriority.NORMAL
                    elif retry_priority <= ScanPriority.HIGH.value:
                        job.priority = ScanPriority.HIGH
                    else:
                        job.priority = ScanPriority.CRITICAL
                    job.priority = retry_priority
                    
                    # Add back to queue for retry
                    priority_value = -job.priority.value
                    self.job_queue.put((priority_value, time.time(), job))
                    
                    log_info(f"Retrying scan {scan_id} (attempt {job.retry_count}/{job.max_retries})")
                else:
                    # Max retries reached, mark as permanently failed
                    del self.jobs[scan_id]
                    log_error(f"Scan {scan_id} failed permanently after {job.retry_count} attempts")
        
        # Update database
        try:
            session = db_service.get_session()
            from database.models import ScanQueue
            
            queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
            if queue_entry:
                if scan_id in self.jobs:  # Still retrying
                    queue_entry.status = 'retrying'
                    queue_entry.retry_count = self.jobs[scan_id].retry_count
                else:  # Permanently failed
                    queue_entry.status = 'failed'
                    queue_entry.error_message = error_message
                session.commit()
            session.close()
        except Exception as e:
            log_error("Failed to update scan job failure in database", error=e)
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status."""
        with self.lock:
            return {
                'running': self.running,
                'workers': len(self.workers),
                'queued_jobs': self.job_queue.qsize(),
                'active_jobs': len(self.jobs),
                'worker_status': [
                    {
                        'worker_id': worker.worker_id,
                        'current_job': worker.current_job.scan_id if worker.current_job else None
                    }
                    for worker in self.workers
                ]
            }
    
    def cancel_job(self, scan_id: str) -> bool:
        """Cancel a queued or running job."""
        try:
            with self.lock:
                if scan_id in self.jobs:
                    del self.jobs[scan_id]
            
            # Update database
            session = db_service.get_session()
            from database.models import ScanQueue
            
            queue_entry = session.query(ScanQueue).filter_by(scan_id=scan_id).first()
            if queue_entry:
                queue_entry.status = 'cancelled'
                session.commit()
            session.close()
            
            # Update scan status
            db_service.update_scan_status(scan_id, 'failed', error_message='Cancelled by user')
            
            log_info(f"Cancelled scan job {scan_id}")
            return True
            
        except Exception as e:
            log_error(f"Failed to cancel scan job {scan_id}", error=e)
            return False

# Global scan queue manager instance
scan_queue_manager = ScanQueueManager(max_workers=3)