#!/usr/bin/env python3
"""
Team Collaboration Manager for InfoSentinel Enterprise.
Provides team collaboration features, role-based permissions, and workflow management.
"""
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from database.db import get_postgres_session, close_postgres_session
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from enterprise.tenant_manager import UserRole

logger = logging.getLogger(__name__)
Base = declarative_base()

class TeamType(Enum):
    """Team types for different purposes."""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    DEVOPS = "devops"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    CUSTOM = "custom"

class TaskStatus(Enum):
    """Task status types."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REVIEW = "review"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"

class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class NotificationType(Enum):
    """Notification types."""
    TASK_ASSIGNED = "task_assigned"
    TASK_COMPLETED = "task_completed"
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITY_FOUND = "vulnerability_found"
    REPORT_READY = "report_ready"
    TEAM_INVITATION = "team_invitation"
    COMMENT_ADDED = "comment_added"
    DEADLINE_APPROACHING = "deadline_approaching"

@dataclass
class CollaborationPermissions:
    """Collaboration-specific permissions."""
    can_create_teams: bool
    can_manage_teams: bool
    can_assign_tasks: bool
    can_view_all_tasks: bool
    can_create_workflows: bool
    can_manage_workflows: bool
    can_export_data: bool
    can_manage_integrations: bool

class Team(Base):
    """Team model for collaboration."""
    __tablename__ = 'teams'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    team_type = Column(String(50), default=TeamType.CUSTOM.value)
    
    # Team settings
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    settings = Column(Text)  # JSON for team-specific settings
    
    # Metadata
    created_by = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    members = relationship("TeamMember", back_populates="team")
    tasks = relationship("CollaborationTask", back_populates="team")
    workflows = relationship("Workflow", back_populates="team")

class TeamMember(Base):
    """Team membership model."""
    __tablename__ = 'team_members'
    
    id = Column(Integer, primary_key=True)
    team_id = Column(Integer, ForeignKey('teams.id'), nullable=False)
    user_id = Column(Integer, nullable=False)
    role = Column(String(50), default='member')  # lead, member, observer
    
    # Permissions
    permissions = Column(Text)  # JSON array of team-specific permissions
    
    # Status
    is_active = Column(Boolean, default=True)
    joined_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    team = relationship("Team", back_populates="members")

class CollaborationTask(Base):
    """Task model for team collaboration."""
    __tablename__ = 'collaboration_tasks'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    team_id = Column(Integer, ForeignKey('teams.id'))
    
    # Task details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    task_type = Column(String(100))  # vulnerability_remediation, compliance_check, etc.
    status = Column(String(20), default=TaskStatus.OPEN.value)
    priority = Column(String(20), default=TaskPriority.MEDIUM.value)
    
    # Assignment
    assigned_to = Column(Integer)  # User ID
    assigned_by = Column(Integer, nullable=False)  # User ID
    
    # Timing
    due_date = Column(DateTime)
    estimated_hours = Column(Float)
    actual_hours = Column(Float)
    
    # Context
    related_scan_id = Column(Integer)
    related_vulnerability_id = Column(Integer)
    related_asset_id = Column(Integer)
    
    # Metadata
    tags = Column(Text)  # JSON array of tags
    custom_fields = Column(Text)  # JSON for custom fields
    
    # Tracking
    created_by = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationships
    team = relationship("Team", back_populates="tasks")
    comments = relationship("TaskComment", back_populates="task")
    attachments = relationship("TaskAttachment", back_populates="task")
    time_logs = relationship("TaskTimeLog", back_populates="task")

class TaskComment(Base):
    """Task comment model."""
    __tablename__ = 'task_comments'
    
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('collaboration_tasks.id'), nullable=False)
    user_id = Column(Integer, nullable=False)
    
    # Comment content
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)  # Internal vs external comments
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    task = relationship("CollaborationTask", back_populates="comments")

class TaskAttachment(Base):
    """Task attachment model."""
    __tablename__ = 'task_attachments'
    
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('collaboration_tasks.id'), nullable=False)
    user_id = Column(Integer, nullable=False)
    
    # File details
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer)
    mime_type = Column(String(100))
    
    # Metadata
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    task = relationship("CollaborationTask", back_populates="attachments")

class TaskTimeLog(Base):
    """Task time tracking model."""
    __tablename__ = 'task_time_logs'
    
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('collaboration_tasks.id'), nullable=False)
    user_id = Column(Integer, nullable=False)
    
    # Time tracking
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    duration_minutes = Column(Integer)
    description = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    task = relationship("CollaborationTask", back_populates="time_logs")

class Workflow(Base):
    """Workflow model for automated processes."""
    __tablename__ = 'workflows'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    team_id = Column(Integer, ForeignKey('teams.id'))
    
    # Workflow details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    workflow_type = Column(String(100))  # vulnerability_response, compliance_check, etc.
    
    # Configuration
    trigger_conditions = Column(Text)  # JSON for trigger conditions
    workflow_steps = Column(Text)  # JSON for workflow steps
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_by = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    team = relationship("Team", back_populates="workflows")
    executions = relationship("WorkflowExecution", back_populates="workflow")

class WorkflowExecution(Base):
    """Workflow execution tracking."""
    __tablename__ = 'workflow_executions'
    
    id = Column(Integer, primary_key=True)
    workflow_id = Column(Integer, ForeignKey('workflows.id'), nullable=False)
    
    # Execution details
    trigger_data = Column(Text)  # JSON data that triggered the workflow
    execution_status = Column(String(50), default='running')
    current_step = Column(Integer, default=0)
    
    # Results
    execution_log = Column(Text)  # JSON log of execution steps
    error_message = Column(Text)
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationships
    workflow = relationship("Workflow", back_populates="executions")

class Notification(Base):
    """Notification model for team communication."""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    user_id = Column(Integer, nullable=False)
    
    # Notification details
    notification_type = Column(String(50), nullable=False)
    title = Column(String(500), nullable=False)
    message = Column(Text)
    
    # Context
    related_object_type = Column(String(100))  # task, scan, vulnerability, etc.
    related_object_id = Column(Integer)
    
    # Status
    is_read = Column(Boolean, default=False)
    is_dismissed = Column(Boolean, default=False)
    
    # Delivery
    delivery_methods = Column(Text)  # JSON array: email, in_app, slack, etc.
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime)

class CollaborationManager:
    """
    Team collaboration and workflow management.
    """
    
    def __init__(self):
        """
        Initialize the collaboration manager.
        """
        # Role-based collaboration permissions
        self.role_collaboration_permissions = {
            UserRole.OWNER: CollaborationPermissions(
                can_create_teams=True,
                can_manage_teams=True,
                can_assign_tasks=True,
                can_view_all_tasks=True,
                can_create_workflows=True,
                can_manage_workflows=True,
                can_export_data=True,
                can_manage_integrations=True
            ),
            UserRole.ADMIN: CollaborationPermissions(
                can_create_teams=True,
                can_manage_teams=True,
                can_assign_tasks=True,
                can_view_all_tasks=True,
                can_create_workflows=True,
                can_manage_workflows=True,
                can_export_data=True,
                can_manage_integrations=False
            ),
            UserRole.MANAGER: CollaborationPermissions(
                can_create_teams=True,
                can_manage_teams=False,
                can_assign_tasks=True,
                can_view_all_tasks=True,
                can_create_workflows=False,
                can_manage_workflows=False,
                can_export_data=True,
                can_manage_integrations=False
            ),
            UserRole.ANALYST: CollaborationPermissions(
                can_create_teams=False,
                can_manage_teams=False,
                can_assign_tasks=False,
                can_view_all_tasks=False,
                can_create_workflows=False,
                can_manage_workflows=False,
                can_export_data=False,
                can_manage_integrations=False
            ),
            UserRole.VIEWER: CollaborationPermissions(
                can_create_teams=False,
                can_manage_teams=False,
                can_assign_tasks=False,
                can_view_all_tasks=False,
                can_create_workflows=False,
                can_manage_workflows=False,
                can_export_data=False,
                can_manage_integrations=False
            )
        }
        
        # Default workflow templates
        self.workflow_templates = {
            'vulnerability_response': {
                'name': 'Vulnerability Response Workflow',
                'description': 'Automated workflow for vulnerability remediation',
                'steps': [
                    {'action': 'create_task', 'params': {'title': 'Assess vulnerability', 'priority': 'high'}},
                    {'action': 'assign_to_team', 'params': {'team_type': 'security'}},
                    {'action': 'set_deadline', 'params': {'days': 7}},
                    {'action': 'notify_stakeholders', 'params': {'roles': ['admin', 'manager']}}
                ]
            },
            'compliance_check': {
                'name': 'Compliance Check Workflow',
                'description': 'Automated compliance verification process',
                'steps': [
                    {'action': 'create_task', 'params': {'title': 'Compliance verification', 'priority': 'medium'}},
                    {'action': 'assign_to_team', 'params': {'team_type': 'compliance'}},
                    {'action': 'schedule_review', 'params': {'days': 14}},
                    {'action': 'generate_report', 'params': {'type': 'compliance'}}
                ]
            }
        }
    
    def create_team(self, organization_id: int, name: str, description: str,
                   team_type: TeamType, created_by: int, members: List[int] = None) -> Dict:
        """
        Create a new team.
        
        Args:
            organization_id: Organization ID
            name: Team name
            description: Team description
            team_type: Type of team
            created_by: User ID creating the team
            members: List of user IDs to add as members
            
        Returns:
            Team creation result
        """
        try:
            session = get_postgres_session()
            
            # Create team
            team = Team(
                organization_id=organization_id,
                name=name,
                description=description,
                team_type=team_type.value,
                created_by=created_by
            )
            
            session.add(team)
            session.flush()  # Get the ID
            
            # Add creator as team lead
            creator_member = TeamMember(
                team_id=team.id,
                user_id=created_by,
                role='lead',
                permissions=json.dumps(['manage_team', 'assign_tasks', 'manage_members'])
            )
            
            session.add(creator_member)
            
            # Add other members
            if members:
                for user_id in members:
                    if user_id != created_by:  # Don't add creator twice
                        member = TeamMember(
                            team_id=team.id,
                            user_id=user_id,
                            role='member',
                            permissions=json.dumps(['view_tasks', 'update_tasks'])
                        )
                        session.add(member)
            
            session.commit()
            
            logger.info(f"Team created: {name} (ID: {team.id})")
            
            return {
                'success': True,
                'team': {
                    'id': team.id,
                    'name': team.name,
                    'description': team.description,
                    'team_type': team.team_type,
                    'created_at': team.created_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating team: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def create_task(self, organization_id: int, title: str, description: str,
                   task_type: str, assigned_to: int, assigned_by: int,
                   team_id: int = None, priority: TaskPriority = TaskPriority.MEDIUM,
                   due_date: datetime = None, **kwargs) -> Dict:
        """
        Create a new collaboration task.
        
        Args:
            organization_id: Organization ID
            title: Task title
            description: Task description
            task_type: Type of task
            assigned_to: User ID to assign task to
            assigned_by: User ID creating the task
            team_id: Optional team ID
            priority: Task priority
            due_date: Optional due date
            **kwargs: Additional task fields
            
        Returns:
            Task creation result
        """
        try:
            session = get_postgres_session()
            
            # Create task
            task = CollaborationTask(
                organization_id=organization_id,
                team_id=team_id,
                title=title,
                description=description,
                task_type=task_type,
                assigned_to=assigned_to,
                assigned_by=assigned_by,
                priority=priority.value,
                due_date=due_date,
                created_by=assigned_by,
                **{k: v for k, v in kwargs.items() if hasattr(CollaborationTask, k)}
            )
            
            session.add(task)
            session.flush()
            
            # Create notification for assigned user
            notification = Notification(
                organization_id=organization_id,
                user_id=assigned_to,
                notification_type=NotificationType.TASK_ASSIGNED.value,
                title=f"New task assigned: {title}",
                message=f"You have been assigned a new {priority.value} priority task.",
                related_object_type='task',
                related_object_id=task.id,
                delivery_methods=json.dumps(['in_app', 'email'])
            )
            
            session.add(notification)
            session.commit()
            
            logger.info(f"Task created: {title} (ID: {task.id})")
            
            return {
                'success': True,
                'task': {
                    'id': task.id,
                    'title': task.title,
                    'status': task.status,
                    'priority': task.priority,
                    'assigned_to': task.assigned_to,
                    'due_date': task.due_date.isoformat() if task.due_date else None,
                    'created_at': task.created_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating task: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def update_task_status(self, task_id: int, new_status: TaskStatus, 
                          user_id: int, comment: str = None) -> Dict:
        """
        Update task status.
        
        Args:
            task_id: Task ID
            new_status: New status
            user_id: User ID making the update
            comment: Optional comment
            
        Returns:
            Update result
        """
        try:
            session = get_postgres_session()
            
            task = session.query(CollaborationTask).filter(
                CollaborationTask.id == task_id
            ).first()
            
            if not task:
                return {
                    'success': False,
                    'error': 'Task not found'
                }
            
            old_status = task.status
            task.status = new_status.value
            task.updated_at = datetime.utcnow()
            
            if new_status == TaskStatus.COMPLETED:
                task.completed_at = datetime.utcnow()
            
            # Add comment if provided
            if comment:
                task_comment = TaskComment(
                    task_id=task.id,
                    user_id=user_id,
                    content=comment
                )
                session.add(task_comment)
            
            # Create notification for task completion
            if new_status == TaskStatus.COMPLETED:
                notification = Notification(
                    organization_id=task.organization_id,
                    user_id=task.assigned_by,
                    notification_type=NotificationType.TASK_COMPLETED.value,
                    title=f"Task completed: {task.title}",
                    message=f"Task has been marked as completed.",
                    related_object_type='task',
                    related_object_id=task.id,
                    delivery_methods=json.dumps(['in_app', 'email'])
                )
                session.add(notification)
            
            session.commit()
            
            logger.info(f"Task {task_id} status updated: {old_status} -> {new_status.value}")
            
            return {
                'success': True,
                'task': {
                    'id': task.id,
                    'status': task.status,
                    'updated_at': task.updated_at.isoformat(),
                    'completed_at': task.completed_at.isoformat() if task.completed_at else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating task status: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def add_task_comment(self, task_id: int, user_id: int, content: str, 
                        is_internal: bool = True) -> Dict:
        """
        Add comment to a task.
        
        Args:
            task_id: Task ID
            user_id: User ID adding comment
            content: Comment content
            is_internal: Whether comment is internal
            
        Returns:
            Comment creation result
        """
        try:
            session = get_postgres_session()
            
            # Verify task exists
            task = session.query(CollaborationTask).filter(
                CollaborationTask.id == task_id
            ).first()
            
            if not task:
                return {
                    'success': False,
                    'error': 'Task not found'
                }
            
            # Create comment
            comment = TaskComment(
                task_id=task_id,
                user_id=user_id,
                content=content,
                is_internal=is_internal
            )
            
            session.add(comment)
            
            # Update task timestamp
            task.updated_at = datetime.utcnow()
            
            # Notify relevant users
            notification_users = [task.assigned_to, task.assigned_by]
            for notify_user_id in set(notification_users):
                if notify_user_id != user_id:  # Don't notify the commenter
                    notification = Notification(
                        organization_id=task.organization_id,
                        user_id=notify_user_id,
                        notification_type=NotificationType.COMMENT_ADDED.value,
                        title=f"New comment on: {task.title}",
                        message=f"A new comment has been added to the task.",
                        related_object_type='task',
                        related_object_id=task.id,
                        delivery_methods=json.dumps(['in_app'])
                    )
                    session.add(notification)
            
            session.commit()
            
            return {
                'success': True,
                'comment': {
                    'id': comment.id,
                    'content': comment.content,
                    'user_id': comment.user_id,
                    'created_at': comment.created_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error adding task comment: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def log_time(self, task_id: int, user_id: int, start_time: datetime,
                end_time: datetime = None, description: str = None) -> Dict:
        """
        Log time spent on a task.
        
        Args:
            task_id: Task ID
            user_id: User ID logging time
            start_time: Start time
            end_time: End time (defaults to now)
            description: Optional description
            
        Returns:
            Time log result
        """
        try:
            session = get_postgres_session()
            
            if not end_time:
                end_time = datetime.utcnow()
            
            # Calculate duration
            duration = end_time - start_time
            duration_minutes = int(duration.total_seconds() / 60)
            
            # Create time log
            time_log = TaskTimeLog(
                task_id=task_id,
                user_id=user_id,
                start_time=start_time,
                end_time=end_time,
                duration_minutes=duration_minutes,
                description=description
            )
            
            session.add(time_log)
            
            # Update task actual hours
            task = session.query(CollaborationTask).filter(
                CollaborationTask.id == task_id
            ).first()
            
            if task:
                if task.actual_hours:
                    task.actual_hours += duration_minutes / 60
                else:
                    task.actual_hours = duration_minutes / 60
            
            session.commit()
            
            return {
                'success': True,
                'time_log': {
                    'id': time_log.id,
                    'duration_minutes': duration_minutes,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error logging time: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def get_team_dashboard(self, team_id: int) -> Dict:
        """
        Get team dashboard data.
        
        Args:
            team_id: Team ID
            
        Returns:
            Team dashboard data
        """
        try:
            session = get_postgres_session()
            
            # Get team info
            team = session.query(Team).filter(Team.id == team_id).first()
            if not team:
                return {'error': 'Team not found'}
            
            # Get team members
            members = session.query(TeamMember).filter(
                TeamMember.team_id == team_id,
                TeamMember.is_active == True
            ).all()
            
            # Get team tasks
            tasks = session.query(CollaborationTask).filter(
                CollaborationTask.team_id == team_id
            ).all()
            
            # Calculate task statistics
            task_stats = {
                'total': len(tasks),
                'open': len([t for t in tasks if t.status == TaskStatus.OPEN.value]),
                'in_progress': len([t for t in tasks if t.status == TaskStatus.IN_PROGRESS.value]),
                'completed': len([t for t in tasks if t.status == TaskStatus.COMPLETED.value]),
                'overdue': len([t for t in tasks if t.due_date and t.due_date < datetime.utcnow() and t.status not in [TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value]])
            }
            
            # Get recent activity
            recent_tasks = session.query(CollaborationTask).filter(
                CollaborationTask.team_id == team_id
            ).order_by(CollaborationTask.updated_at.desc()).limit(10).all()
            
            return {
                'team': {
                    'id': team.id,
                    'name': team.name,
                    'description': team.description,
                    'team_type': team.team_type,
                    'member_count': len(members)
                },
                'task_statistics': task_stats,
                'recent_tasks': [
                    {
                        'id': task.id,
                        'title': task.title,
                        'status': task.status,
                        'priority': task.priority,
                        'assigned_to': task.assigned_to,
                        'updated_at': task.updated_at.isoformat()
                    } for task in recent_tasks
                ],
                'members': [
                    {
                        'user_id': member.user_id,
                        'role': member.role,
                        'joined_at': member.joined_at.isoformat()
                    } for member in members
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting team dashboard: {str(e)}")
            return {'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def get_user_tasks(self, user_id: int, organization_id: int, 
                      status_filter: List[str] = None) -> List[Dict]:
        """
        Get tasks assigned to a user.
        
        Args:
            user_id: User ID
            organization_id: Organization ID
            status_filter: Optional status filter
            
        Returns:
            List of user tasks
        """
        try:
            session = get_postgres_session()
            
            query = session.query(CollaborationTask).filter(
                CollaborationTask.assigned_to == user_id,
                CollaborationTask.organization_id == organization_id
            )
            
            if status_filter:
                query = query.filter(CollaborationTask.status.in_(status_filter))
            
            tasks = query.order_by(CollaborationTask.due_date.asc()).all()
            
            task_list = []
            for task in tasks:
                task_list.append({
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'status': task.status,
                    'priority': task.priority,
                    'task_type': task.task_type,
                    'due_date': task.due_date.isoformat() if task.due_date else None,
                    'estimated_hours': task.estimated_hours,
                    'actual_hours': task.actual_hours,
                    'assigned_by': task.assigned_by,
                    'team_id': task.team_id,
                    'created_at': task.created_at.isoformat(),
                    'updated_at': task.updated_at.isoformat()
                })
            
            return task_list
            
        except Exception as e:
            logger.error(f"Error getting user tasks: {str(e)}")
            return []
        finally:
            close_postgres_session(session)
    
    def create_workflow(self, organization_id: int, name: str, description: str,
                       workflow_type: str, trigger_conditions: Dict,
                       workflow_steps: List[Dict], created_by: int,
                       team_id: int = None) -> Dict:
        """
        Create a new workflow.
        
        Args:
            organization_id: Organization ID
            name: Workflow name
            description: Workflow description
            workflow_type: Type of workflow
            trigger_conditions: Conditions that trigger the workflow
            workflow_steps: Steps in the workflow
            created_by: User ID creating the workflow
            team_id: Optional team ID
            
        Returns:
            Workflow creation result
        """
        try:
            session = get_postgres_session()
            
            workflow = Workflow(
                organization_id=organization_id,
                team_id=team_id,
                name=name,
                description=description,
                workflow_type=workflow_type,
                trigger_conditions=json.dumps(trigger_conditions),
                workflow_steps=json.dumps(workflow_steps),
                created_by=created_by
            )
            
            session.add(workflow)
            session.commit()
            
            logger.info(f"Workflow created: {name} (ID: {workflow.id})")
            
            return {
                'success': True,
                'workflow': {
                    'id': workflow.id,
                    'name': workflow.name,
                    'workflow_type': workflow.workflow_type,
                    'is_active': workflow.is_active,
                    'created_at': workflow.created_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating workflow: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def get_notifications(self, user_id: int, organization_id: int, 
                         unread_only: bool = False) -> List[Dict]:
        """
        Get user notifications.
        
        Args:
            user_id: User ID
            organization_id: Organization ID
            unread_only: Whether to return only unread notifications
            
        Returns:
            List of notifications
        """
        try:
            session = get_postgres_session()
            
            query = session.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.organization_id == organization_id
            )
            
            if unread_only:
                query = query.filter(Notification.is_read == False)
            
            notifications = query.order_by(Notification.created_at.desc()).limit(50).all()
            
            notification_list = []
            for notification in notifications:
                notification_list.append({
                    'id': notification.id,
                    'type': notification.notification_type,
                    'title': notification.title,
                    'message': notification.message,
                    'is_read': notification.is_read,
                    'related_object_type': notification.related_object_type,
                    'related_object_id': notification.related_object_id,
                    'created_at': notification.created_at.isoformat(),
                    'read_at': notification.read_at.isoformat() if notification.read_at else None
                })
            
            return notification_list
            
        except Exception as e:
            logger.error(f"Error getting notifications: {str(e)}")
            return []
        finally:
            close_postgres_session(session)
    
    def mark_notification_read(self, notification_id: int, user_id: int) -> bool:
        """
        Mark notification as read.
        
        Args:
            notification_id: Notification ID
            user_id: User ID
            
        Returns:
            Success status
        """
        try:
            session = get_postgres_session()
            
            notification = session.query(Notification).filter(
                Notification.id == notification_id,
                Notification.user_id == user_id
            ).first()
            
            if notification:
                notification.is_read = True
                notification.read_at = datetime.utcnow()
                session.commit()
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error marking notification read: {str(e)}")
            return False
        finally:
            close_postgres_session(session)
    
    def get_collaboration_analytics(self, organization_id: int, 
                                  period_days: int = 30) -> Dict:
        """
        Get collaboration analytics.
        
        Args:
            organization_id: Organization ID
            period_days: Analysis period in days
            
        Returns:
            Collaboration analytics
        """
        try:
            session = get_postgres_session()
            
            start_date = datetime.utcnow() - timedelta(days=period_days)
            
            # Task statistics
            tasks = session.query(CollaborationTask).filter(
                CollaborationTask.organization_id == organization_id,
                CollaborationTask.created_at >= start_date
            ).all()
            
            # Team statistics
            teams = session.query(Team).filter(
                Team.organization_id == organization_id,
                Team.is_active == True
            ).all()
            
            # Calculate metrics
            task_completion_rate = 0
            if tasks:
                completed_tasks = len([t for t in tasks if t.status == TaskStatus.COMPLETED.value])
                task_completion_rate = (completed_tasks / len(tasks)) * 100
            
            # Average task completion time
            completed_tasks = [t for t in tasks if t.completed_at and t.created_at]
            avg_completion_time = 0
            if completed_tasks:
                completion_times = [(t.completed_at - t.created_at).days for t in completed_tasks]
                avg_completion_time = sum(completion_times) / len(completion_times)
            
            return {
                'period_days': period_days,
                'task_statistics': {
                    'total_tasks': len(tasks),
                    'completed_tasks': len([t for t in tasks if t.status == TaskStatus.COMPLETED.value]),
                    'in_progress_tasks': len([t for t in tasks if t.status == TaskStatus.IN_PROGRESS.value]),
                    'overdue_tasks': len([t for t in tasks if t.due_date and t.due_date < datetime.utcnow() and t.status not in [TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value]]),
                    'completion_rate': round(task_completion_rate, 2),
                    'avg_completion_time_days': round(avg_completion_time, 1)
                },
                'team_statistics': {
                    'total_teams': len(teams),
                    'active_teams': len([t for t in teams if t.is_active]),
                    'avg_team_size': round(sum([len(t.members) for t in teams]) / len(teams), 1) if teams else 0
                },
                'productivity_metrics': {
                    'tasks_per_day': round(len(tasks) / period_days, 2),
                    'completion_velocity': round(len([t for t in tasks if t.status == TaskStatus.COMPLETED.value]) / period_days, 2)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting collaboration analytics: {str(e)}")
            return {}
        finally:
            close_postgres_session(session)