#!/usr/bin/env python3
"""
Main application file for the Automated Penetration Testing Platform.
"""
import os
from flask import Flask, jsonify
from flask_cors import CORS
try:
    from flask_socketio import SocketIO  # Optional
except Exception:
    SocketIO = None
try:
    from flask_sqlalchemy import SQLAlchemy  # Optional if DB disabled
except Exception:
    SQLAlchemy = None
try:
    from flask_mail import Mail  # Optional
except Exception:
    Mail = None
from dotenv import load_dotenv
import eventlet

# Import modules
from api.routes import register_routes
# Lazy import initialize_db only when needed to avoid requiring SQLAlchemy at import time
# from database.db import initialize_db

# Optional services
try:
    from services.websocket_service import register_websocket_events
except Exception:
    register_websocket_events = None
try:
    from services.celery_service import make_celery
except Exception:
    make_celery = None

# Load environment variables
load_dotenv()

# Initialize extensions
if SQLAlchemy is not None:
    db = SQLAlchemy()
else:
    db = None

socketio = SocketIO(cors_allowed_origins="*", async_mode='eventlet') if SocketIO is not None else None
mail = Mail() if Mail is not None else None

def create_app():
    """Initialize and configure the Flask application."""
    app = Flask(__name__)
    
    # Configure application
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL', 
        'postgresql://postgres:password@localhost:5432/pentest_db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/pentest')
    
    # Redis configuration for Celery
    app.config['CELERY_BROKER_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    app.config['CELERY_RESULT_BACKEND'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Mail configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    
    # Initialize extensions
    CORS(app)

    # Allow disabling database initialization for local/dev without Postgres
    disable_db = os.getenv('DISABLE_DB', 'false').lower() == 'true'
    if not disable_db and SQLAlchemy is not None:
        # Initialize SQLAlchemy
        from database.db import initialize_db  # lazy import
        global db
        if db is None:
            db = SQLAlchemy()
        db.init_app(app)
        # Initialize databases (SQLAlchemy + Mongo, if configured)
        initialize_db(app)
    else:
        # Set a flag so the app knows DB features are disabled
        app.config['DB_DISABLED'] = True

    # Initialize optional integrations
    global socketio, mail
    if socketio is not None:
        socketio.init_app(app)
    if mail is not None:
        mail.init_app(app)
    
    # Register API routes
    register_routes(app)
    
    # Register WebSocket events if available
    if register_websocket_events is not None and socketio is not None:
        register_websocket_events(socketio)
    
    # Initialize Celery if available
    celery = None
    if make_celery is not None:
        try:
            celery = make_celery(app)
        except Exception:
            celery = None
    app.celery = celery
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        return jsonify({
            "status": "healthy", 
            "version": "2.0.0",
            "features": {
                "websockets": socketio is not None,
                "real_scanning": True,
                "database": not disable_db and SQLAlchemy is not None,
                "reports": True,
                "celery": celery is not None
            }
        })
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('PORT', 5000))
    
    # Use eventlet for WebSocket support if available
    if socketio is not None:
        try:
            eventlet.monkey_patch()
        except Exception:
            pass
        socketio.run(app, host='0.0.0.0', port=port, debug=app.config['DEBUG'])
    else:
        app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])