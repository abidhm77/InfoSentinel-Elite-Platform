#!/bin/bash

# InfoSentinel Enhanced Backend Stop Script
# This script stops all backend services gracefully

echo "🛑 Stopping InfoSentinel Enhanced Backend Services..."

# Function to stop process by PID file
stop_process() {
    local pidfile=$1
    local service_name=$2
    
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if ps -p $pid > /dev/null 2>&1; then
            echo "🔄 Stopping $service_name (PID: $pid)..."
            kill $pid
            
            # Wait for process to stop
            local count=0
            while ps -p $pid > /dev/null 2>&1 && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            if ps -p $pid > /dev/null 2>&1; then
                echo "⚠️  Force killing $service_name..."
                kill -9 $pid
            fi
            
            echo "✅ $service_name stopped"
        else
            echo "ℹ️  $service_name was not running"
        fi
        
        # Remove PID file
        rm -f "$pidfile"
    else
        echo "ℹ️  No PID file found for $service_name"
    fi
}

# Stop Celery worker
stop_process "logs/celery_worker.pid" "Celery Worker"

# Stop Celery beat scheduler
stop_process "logs/celery_beat.pid" "Celery Beat Scheduler"

# Stop any remaining Celery processes
echo "🔍 Checking for remaining Celery processes..."
celery_pids=$(pgrep -f "celery.*worker")
if [ ! -z "$celery_pids" ]; then
    echo "🔄 Stopping remaining Celery processes..."
    echo $celery_pids | xargs kill
    sleep 2
    
    # Force kill if still running
    celery_pids=$(pgrep -f "celery.*worker")
    if [ ! -z "$celery_pids" ]; then
        echo "⚠️  Force killing remaining Celery processes..."
        echo $celery_pids | xargs kill -9
    fi
fi

# Stop Flask application (if running in background)
flask_pids=$(pgrep -f "python.*app.py")
if [ ! -z "$flask_pids" ]; then
    echo "🔄 Stopping Flask application..."
    echo $flask_pids | xargs kill
    sleep 2
    
    # Force kill if still running
    flask_pids=$(pgrep -f "python.*app.py")
    if [ ! -z "$flask_pids" ]; then
        echo "⚠️  Force killing Flask application..."
        echo $flask_pids | xargs kill -9
    fi
    echo "✅ Flask application stopped"
fi

# Clean up temporary files
echo "🧹 Cleaning up temporary files..."
rm -f logs/*.pid
rm -f temp/*

echo "✅ All InfoSentinel Enhanced Backend services stopped successfully!"
echo "📊 Service status:"
echo "   - Celery Worker: Stopped"
echo "   - Celery Beat: Stopped"
echo "   - Flask App: Stopped"
echo "   - WebSocket: Stopped"
echo ""
echo "💡 To restart services, run: ./start_enhanced_backend.sh"