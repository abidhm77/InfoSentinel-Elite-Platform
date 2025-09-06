#!/usr/bin/env python3
"""
WebSocket service for real-time communication with frontend.
"""
from flask_socketio import emit, join_room, leave_room
from flask import request
import logging

logger = logging.getLogger(__name__)

def register_websocket_events(socketio):
    """
    Register WebSocket event handlers.
    
    Args:
        socketio: SocketIO instance
    """
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        logger.info(f"Client connected: {request.sid}")
        emit('connected', {'status': 'Connected to InfoSentinel'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('join_scan')
    def handle_join_scan(data):
        """Join a scan room for real-time updates."""
        scan_id = data.get('scan_id')
        if scan_id:
            join_room(f"scan_{scan_id}")
            emit('joined_scan', {'scan_id': scan_id, 'status': 'Joined scan room'})
            logger.info(f"Client {request.sid} joined scan room: {scan_id}")
    
    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        """Leave a scan room."""
        scan_id = data.get('scan_id')
        if scan_id:
            leave_room(f"scan_{scan_id}")
            emit('left_scan', {'scan_id': scan_id, 'status': 'Left scan room'})
            logger.info(f"Client {request.sid} left scan room: {scan_id}")
    
    @socketio.on('get_scan_status')
    def handle_get_scan_status(data):
        """Get current scan status."""
        scan_id = data.get('scan_id')
        if scan_id:
            # TODO: Get actual scan status from database
            emit('scan_status', {
                'scan_id': scan_id,
                'status': 'running',
                'progress': 45,
                'current_phase': 'Port scanning'
            })

def emit_scan_progress(socketio, scan_id, progress_data):
    """
    Emit scan progress to all clients in the scan room.
    
    Args:
        socketio: SocketIO instance
        scan_id: Scan identifier
        progress_data: Progress information
    """
    socketio.emit('scan_progress', progress_data, room=f"scan_{scan_id}")
    logger.info(f"Emitted progress for scan {scan_id}: {progress_data.get('progress', 0)}%")

def emit_scan_complete(socketio, scan_id, results):
    """
    Emit scan completion to all clients in the scan room.
    
    Args:
        socketio: SocketIO instance
        scan_id: Scan identifier
        results: Scan results
    """
    socketio.emit('scan_complete', {
        'scan_id': scan_id,
        'status': 'completed',
        'results': results
    }, room=f"scan_{scan_id}")
    logger.info(f"Emitted completion for scan {scan_id}")

def emit_scan_error(socketio, scan_id, error_message):
    """
    Emit scan error to all clients in the scan room.
    
    Args:
        socketio: SocketIO instance
        scan_id: Scan identifier
        error_message: Error message
    """
    socketio.emit('scan_error', {
        'scan_id': scan_id,
        'status': 'error',
        'error': error_message
    }, room=f"scan_{scan_id}")
    logger.error(f"Emitted error for scan {scan_id}: {error_message}")

def emit_vulnerability_found(socketio, scan_id, vulnerability):
    """
    Emit vulnerability discovery to all clients in the scan room.
    
    Args:
        socketio: SocketIO instance
        scan_id: Scan identifier
        vulnerability: Vulnerability details
    """
    socketio.emit('vulnerability_found', {
        'scan_id': scan_id,
        'vulnerability': vulnerability
    }, room=f"scan_{scan_id}")
    logger.info(f"Emitted vulnerability for scan {scan_id}: {vulnerability.get('title', 'Unknown')}")