#!/bin/bash

# InfoSentinel Enhanced Backend Startup Script
# This script starts all necessary services for the enhanced backend

echo "🚀 Starting InfoSentinel Enhanced Backend Services..."

# Set environment variables
export FLASK_APP=backend/app.py
export FLASK_ENV=development
export DEBUG=True

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Install/upgrade dependencies
echo "📚 Installing/upgrading dependencies..."
pip install -r backend/requirements.txt

# Check if Redis is running (required for Celery)
echo "🔍 Checking Redis server..."
if ! redis-cli ping > /dev/null 2>&1; then
    echo "⚠️  Redis server is not running. Please start Redis first:"
    echo "   brew services start redis  (macOS with Homebrew)"
    echo "   sudo systemctl start redis (Linux)"
    echo "   Or install Redis: https://redis.io/download"
    exit 1
fi

# Check if PostgreSQL is available (optional but recommended)
echo "🔍 Checking PostgreSQL availability..."
if command -v psql > /dev/null 2>&1; then
    echo "✅ PostgreSQL is available"
else
    echo "⚠️  PostgreSQL not found. Install for full functionality:"
    echo "   brew install postgresql  (macOS with Homebrew)"
    echo "   sudo apt-get install postgresql  (Ubuntu/Debian)"
fi

# Check if MongoDB is available
echo "🔍 Checking MongoDB availability..."
if command -v mongod > /dev/null 2>&1; then
    echo "✅ MongoDB is available"
else
    echo "⚠️  MongoDB not found. Install for full functionality:"
    echo "   brew install mongodb-community  (macOS with Homebrew)"
    echo "   sudo apt-get install mongodb  (Ubuntu/Debian)"
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p reports
mkdir -p temp

# Start Celery worker in background
echo "🔄 Starting Celery worker..."
cd backend
celery -A services.celery_service:celery_app worker --loglevel=info --detach --pidfile=../logs/celery_worker.pid --logfile=../logs/celery_worker.log
cd ..

# Start Celery beat scheduler in background (for periodic tasks)
echo "⏰ Starting Celery beat scheduler..."
cd backend
celery -A services.celery_service:celery_app beat --loglevel=info --detach --pidfile=../logs/celery_beat.pid --logfile=../logs/celery_beat.log
cd ..

# Wait a moment for services to start
sleep 2

# Start the Flask application with SocketIO
echo "🌐 Starting Flask application with WebSocket support..."
echo "📊 Dashboard will be available at: http://localhost:5000"
echo "🔌 WebSocket endpoint: ws://localhost:5000/socket.io"
echo "📈 Health check: http://localhost:5000/health"
echo ""
echo "🛑 To stop all services, run: ./stop_enhanced_backend.sh"
echo ""

# Start the main application
python backend/app.py