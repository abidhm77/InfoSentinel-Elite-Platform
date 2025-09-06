#!/usr/bin/env python3
"""
InfoSentinel WebSocket Manager
Real-time communication for scan updates, notifications, and live data
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from fastapi import WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from auth_system import auth_manager, TokenPayload, UserRole
from database_setup import User, get_db
import jwt
import weakref
import threading
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MessageType(Enum):
    """WebSocket message types"""
    # Authentication
    AUTH_REQUEST = "auth_request"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILED = "auth_failed"
    
    # Scan updates
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    
    # Vulnerability updates
    VULNERABILITY_FOUND = "vulnerability_found"
    HOST_DISCOVERED = "host_discovered"
    SERVICE_DISCOVERED = "service_discovered"
    
    # System notifications
    NOTIFICATION = "notification"
    SYSTEM_ALERT = "system_alert"
    USER_MESSAGE = "user_message"
    
    # Real-time data
    STATS_UPDATE = "stats_update"
    ACTIVITY_LOG = "activity_log"
    
    # Connection management
    PING = "ping"
    PONG = "pong"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    
    # Errors
    ERROR = "error"
    INVALID_MESSAGE = "invalid_message"

class NotificationLevel(Enum):
    """Notification severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"

@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    type: MessageType
    data: Dict[str, Any]
    timestamp: datetime
    message_id: str
    user_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type.value,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'message_id': self.message_id,
            'user_id': self.user_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebSocketMessage':
        return cls(
            type=MessageType(data['type']),
            data=data['data'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            message_id=data['message_id'],
            user_id=data.get('user_id')
        )

@dataclass
class ConnectionInfo:
    """Information about a WebSocket connection"""
    connection_id: str
    user_id: Optional[str]
    username: Optional[str]
    role: Optional[UserRole]
    websocket: WebSocket
    connected_at: datetime
    last_ping: datetime
    subscriptions: Set[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'connection_id': self.connection_id,
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role.value if self.role else None,
            'connected_at': self.connected_at.isoformat(),
            'last_ping': self.last_ping.isoformat(),
            'subscriptions': list(self.subscriptions)
        }

class WebSocketManager:
    """Manages WebSocket connections and real-time communication"""
    
    def __init__(self):
        self.connections: Dict[str, ConnectionInfo] = {}
        self.user_connections: Dict[str, Set[str]] = {}  # user_id -> connection_ids
        self.scan_subscribers: Dict[str, Set[str]] = {}  # scan_id -> connection_ids
        self.global_subscribers: Set[str] = set()  # connections subscribed to global events
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self._setup_message_handlers()
        
    def _setup_message_handlers(self):
        """Setup message handlers for different message types"""
        self.message_handlers = {
            MessageType.AUTH_REQUEST: self._handle_auth_request,
            MessageType.SUBSCRIBE: self._handle_subscribe,
            MessageType.UNSUBSCRIBE: self._handle_unsubscribe,
            MessageType.PING: self._handle_ping,
        }
    
    async def connect(self, websocket: WebSocket) -> str:
        """Accept new WebSocket connection"""
        await websocket.accept()
        
        connection_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        connection_info = ConnectionInfo(
            connection_id=connection_id,
            user_id=None,
            username=None,
            role=None,
            websocket=websocket,
            connected_at=now,
            last_ping=now,
            subscriptions=set()
        )
        
        self.connections[connection_id] = connection_info
        
        logger.info(f"WebSocket connection established: {connection_id}")
        
        # Start background tasks if not already running
        if not self.heartbeat_task:
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        if not self.cleanup_task:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        return connection_id
    
    async def disconnect(self, connection_id: str):
        """Handle WebSocket disconnection"""
        if connection_id not in self.connections:
            return
        
        connection_info = self.connections[connection_id]
        
        # Remove from user connections
        if connection_info.user_id:
            if connection_info.user_id in self.user_connections:
                self.user_connections[connection_info.user_id].discard(connection_id)
                if not self.user_connections[connection_info.user_id]:
                    del self.user_connections[connection_info.user_id]
        
        # Remove from scan subscriptions
        for scan_id, subscribers in self.scan_subscribers.items():
            subscribers.discard(connection_id)
        
        # Remove from global subscribers
        self.global_subscribers.discard(connection_id)
        
        # Remove connection
        del self.connections[connection_id]
        
        logger.info(f"WebSocket connection closed: {connection_id}")
    
    async def authenticate_connection(self, connection_id: str, token: str, db: Session) -> bool:
        """Authenticate WebSocket connection with JWT token"""
        if connection_id not in self.connections:
            return False
        
        try:
            # Verify token
            token_payload = auth_manager.verify_token(token)
            if not token_payload:
                await self._send_auth_failed(connection_id, "Invalid or expired token")
                return False
            
            # Get user from database
            user = db.query(User).filter(User.id == token_payload.user_id).first()
            if not user or not user.is_active:
                await self._send_auth_failed(connection_id, "User not found or inactive")
                return False
            
            # Update connection info
            connection_info = self.connections[connection_id]
            connection_info.user_id = str(user.id)
            connection_info.username = user.username
            connection_info.role = user.role
            
            # Add to user connections
            if str(user.id) not in self.user_connections:
                self.user_connections[str(user.id)] = set()
            self.user_connections[str(user.id)].add(connection_id)
            
            # Send authentication success
            await self._send_auth_success(connection_id, user)
            
            logger.info(f"WebSocket connection authenticated: {connection_id} for user {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"WebSocket authentication error: {e}")
            await self._send_auth_failed(connection_id, "Authentication failed")
            return False
    
    async def send_message(self, connection_id: str, message: WebSocketMessage):
        """Send message to specific connection"""
        if connection_id not in self.connections:
            logger.warning(f"Attempted to send message to non-existent connection: {connection_id}")
            return
        
        connection_info = self.connections[connection_id]
        
        try:
            await connection_info.websocket.send_text(json.dumps(message.to_dict()))
        except Exception as e:
            logger.error(f"Failed to send message to {connection_id}: {e}")
            await self.disconnect(connection_id)
    
    async def broadcast_to_user(self, user_id: str, message: WebSocketMessage):
        """Send message to all connections of a specific user"""
        if user_id not in self.user_connections:
            return
        
        connection_ids = list(self.user_connections[user_id])
        for connection_id in connection_ids:
            await self.send_message(connection_id, message)
    
    async def broadcast_to_scan_subscribers(self, scan_id: str, message: WebSocketMessage):
        """Send message to all subscribers of a specific scan"""
        if scan_id not in self.scan_subscribers:
            return
        
        connection_ids = list(self.scan_subscribers[scan_id])
        for connection_id in connection_ids:
            await self.send_message(connection_id, message)
    
    async def broadcast_global(self, message: WebSocketMessage, role_filter: Optional[UserRole] = None):
        """Send message to all global subscribers, optionally filtered by role"""
        connection_ids = list(self.global_subscribers)
        
        for connection_id in connection_ids:
            if connection_id not in self.connections:
                continue
            
            connection_info = self.connections[connection_id]
            
            # Apply role filter if specified
            if role_filter and connection_info.role != role_filter:
                continue
            
            await self.send_message(connection_id, message)
    
    async def handle_message(self, connection_id: str, message_data: str, db: Session):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message_data)
            message = WebSocketMessage.from_dict(data)
            
            # Update last ping time
            if connection_id in self.connections:
                self.connections[connection_id].last_ping = datetime.now(timezone.utc)
            
            # Handle message based on type
            if message.type in self.message_handlers:
                await self.message_handlers[message.type](connection_id, message, db)
            else:
                logger.warning(f"Unhandled message type: {message.type}")
                await self._send_error(connection_id, f"Unhandled message type: {message.type.value}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received from {connection_id}")
            await self._send_error(connection_id, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error handling message from {connection_id}: {e}")
            await self._send_error(connection_id, "Message processing failed")
    
    # Message handlers
    async def _handle_auth_request(self, connection_id: str, message: WebSocketMessage, db: Session):
        """Handle authentication request"""
        token = message.data.get('token')
        if not token:
            await self._send_auth_failed(connection_id, "Token required")
            return
        
        await self.authenticate_connection(connection_id, token, db)
    
    async def _handle_subscribe(self, connection_id: str, message: WebSocketMessage, db: Session):
        """Handle subscription request"""
        if connection_id not in self.connections:
            return
        
        connection_info = self.connections[connection_id]
        
        # Check if user is authenticated
        if not connection_info.user_id:
            await self._send_error(connection_id, "Authentication required for subscriptions")
            return
        
        subscription_type = message.data.get('type')
        subscription_id = message.data.get('id')
        
        if subscription_type == 'scan' and subscription_id:
            # Subscribe to specific scan updates
            if subscription_id not in self.scan_subscribers:
                self.scan_subscribers[subscription_id] = set()
            self.scan_subscribers[subscription_id].add(connection_id)
            connection_info.subscriptions.add(f"scan:{subscription_id}")
            
        elif subscription_type == 'global':
            # Subscribe to global events
            self.global_subscribers.add(connection_id)
            connection_info.subscriptions.add("global")
        
        logger.info(f"Connection {connection_id} subscribed to {subscription_type}:{subscription_id}")
    
    async def _handle_unsubscribe(self, connection_id: str, message: WebSocketMessage, db: Session):
        """Handle unsubscription request"""
        if connection_id not in self.connections:
            return
        
        connection_info = self.connections[connection_id]
        
        subscription_type = message.data.get('type')
        subscription_id = message.data.get('id')
        
        if subscription_type == 'scan' and subscription_id:
            if subscription_id in self.scan_subscribers:
                self.scan_subscribers[subscription_id].discard(connection_id)
            connection_info.subscriptions.discard(f"scan:{subscription_id}")
            
        elif subscription_type == 'global':
            self.global_subscribers.discard(connection_id)
            connection_info.subscriptions.discard("global")
        
        logger.info(f"Connection {connection_id} unsubscribed from {subscription_type}:{subscription_id}")
    
    async def _handle_ping(self, connection_id: str, message: WebSocketMessage, db: Session):
        """Handle ping message"""
        pong_message = WebSocketMessage(
            type=MessageType.PONG,
            data={'timestamp': datetime.now(timezone.utc).isoformat()},
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.send_message(connection_id, pong_message)
    
    # Helper methods for sending specific message types
    async def _send_auth_success(self, connection_id: str, user: User):
        """Send authentication success message"""
        message = WebSocketMessage(
            type=MessageType.AUTH_SUCCESS,
            data={
                'user': {
                    'id': str(user.id),
                    'username': user.username,
                    'role': user.role.value,
                    'email': user.email
                }
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4()),
            user_id=str(user.id)
        )
        await self.send_message(connection_id, message)
    
    async def _send_auth_failed(self, connection_id: str, reason: str):
        """Send authentication failed message"""
        message = WebSocketMessage(
            type=MessageType.AUTH_FAILED,
            data={'reason': reason},
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.send_message(connection_id, message)
    
    async def _send_error(self, connection_id: str, error_message: str):
        """Send error message"""
        message = WebSocketMessage(
            type=MessageType.ERROR,
            data={'message': error_message},
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.send_message(connection_id, message)
    
    # Public methods for sending notifications
    async def send_scan_started(self, scan_id: str, scan_data: Dict[str, Any]):
        """Send scan started notification"""
        message = WebSocketMessage(
            type=MessageType.SCAN_STARTED,
            data={
                'scan_id': scan_id,
                'scan_data': scan_data
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_to_scan_subscribers(scan_id, message)
    
    async def send_scan_progress(self, scan_id: str, progress: int, status: str, details: Dict[str, Any] = None):
        """Send scan progress update"""
        message = WebSocketMessage(
            type=MessageType.SCAN_PROGRESS,
            data={
                'scan_id': scan_id,
                'progress': progress,
                'status': status,
                'details': details or {}
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_to_scan_subscribers(scan_id, message)
    
    async def send_scan_completed(self, scan_id: str, results: Dict[str, Any]):
        """Send scan completed notification"""
        message = WebSocketMessage(
            type=MessageType.SCAN_COMPLETED,
            data={
                'scan_id': scan_id,
                'results': results
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_to_scan_subscribers(scan_id, message)
    
    async def send_vulnerability_found(self, scan_id: str, vulnerability: Dict[str, Any]):
        """Send vulnerability discovered notification"""
        message = WebSocketMessage(
            type=MessageType.VULNERABILITY_FOUND,
            data={
                'scan_id': scan_id,
                'vulnerability': vulnerability
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_to_scan_subscribers(scan_id, message)
    
    async def send_notification(self, user_id: str, title: str, message: str, level: NotificationLevel = NotificationLevel.INFO):
        """Send notification to specific user"""
        notification_message = WebSocketMessage(
            type=MessageType.NOTIFICATION,
            data={
                'title': title,
                'message': message,
                'level': level.value
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4()),
            user_id=user_id
        )
        await self.broadcast_to_user(user_id, notification_message)
    
    async def send_system_alert(self, title: str, message: str, level: NotificationLevel = NotificationLevel.WARNING, role_filter: Optional[UserRole] = None):
        """Send system-wide alert"""
        alert_message = WebSocketMessage(
            type=MessageType.SYSTEM_ALERT,
            data={
                'title': title,
                'message': message,
                'level': level.value
            },
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_global(alert_message, role_filter)
    
    async def send_stats_update(self, stats_data: Dict[str, Any]):
        """Send real-time statistics update"""
        message = WebSocketMessage(
            type=MessageType.STATS_UPDATE,
            data=stats_data,
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_global(message)
    
    async def send_activity_log(self, activity_data: Dict[str, Any]):
        """Send activity log update"""
        message = WebSocketMessage(
            type=MessageType.ACTIVITY_LOG,
            data=activity_data,
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        await self.broadcast_global(message)
    
    # Background tasks
    async def _heartbeat_loop(self):
        """Send periodic heartbeat to detect dead connections"""
        while True:
            try:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
                current_time = datetime.now(timezone.utc)
                dead_connections = []
                
                for connection_id, connection_info in self.connections.items():
                    # Check if connection is stale (no ping in 60 seconds)
                    if (current_time - connection_info.last_ping).total_seconds() > 60:
                        dead_connections.append(connection_id)
                        continue
                    
                    # Send ping
                    try:
                        ping_message = WebSocketMessage(
                            type=MessageType.PING,
                            data={'timestamp': current_time.isoformat()},
                            timestamp=current_time,
                            message_id=str(uuid.uuid4())
                        )
                        await self.send_message(connection_id, ping_message)
                    except Exception as e:
                        logger.error(f"Failed to send heartbeat to {connection_id}: {e}")
                        dead_connections.append(connection_id)
                
                # Clean up dead connections
                for connection_id in dead_connections:
                    await self.disconnect(connection_id)
                
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of stale data"""
        while True:
            try:
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
                # Clean up empty scan subscriptions
                empty_scans = [scan_id for scan_id, subscribers in self.scan_subscribers.items() if not subscribers]
                for scan_id in empty_scans:
                    del self.scan_subscribers[scan_id]
                
                # Clean up empty user connections
                empty_users = [user_id for user_id, connections in self.user_connections.items() if not connections]
                for user_id in empty_users:
                    del self.user_connections[user_id]
                
                logger.info(f"Cleanup completed. Active connections: {len(self.connections)}")
                
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        authenticated_connections = sum(1 for conn in self.connections.values() if conn.user_id)
        
        role_counts = {}
        for conn in self.connections.values():
            if conn.role:
                role_counts[conn.role.value] = role_counts.get(conn.role.value, 0) + 1
        
        return {
            'total_connections': len(self.connections),
            'authenticated_connections': authenticated_connections,
            'anonymous_connections': len(self.connections) - authenticated_connections,
            'global_subscribers': len(self.global_subscribers),
            'scan_subscriptions': len(self.scan_subscribers),
            'role_distribution': role_counts,
            'active_users': len(self.user_connections)
        }
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active connections (admin only)"""
        return [conn.to_dict() for conn in self.connections.values()]

# Global WebSocket manager instance
websocket_manager = WebSocketManager()

# FastAPI WebSocket endpoint handler
async def websocket_endpoint(websocket: WebSocket, db: Session = Depends(get_db)):
    """FastAPI WebSocket endpoint"""
    connection_id = await websocket_manager.connect(websocket)
    
    try:
        while True:
            # Receive message
            message = await websocket.receive_text()
            await websocket_manager.handle_message(connection_id, message, db)
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error for {connection_id}: {e}")
    finally:
        await websocket_manager.disconnect(connection_id)

if __name__ == "__main__":
    # Test WebSocket manager
    import asyncio
    
    async def test_websocket_manager():
        manager = WebSocketManager()
        
        # Test message creation
        test_message = WebSocketMessage(
            type=MessageType.NOTIFICATION,
            data={'title': 'Test', 'message': 'Hello World'},
            timestamp=datetime.now(timezone.utc),
            message_id=str(uuid.uuid4())
        )
        
        print(f"Test message: {test_message.to_dict()}")
        
        # Test connection stats
        stats = manager.get_connection_stats()
        print(f"Connection stats: {stats}")
        
        print("WebSocket manager test completed!")
    
    asyncio.run(test_websocket_manager())