#!/bin/bash

# InfoSentinel AI One-Command Starter
# Zero manual intervention - AI handles everything!

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Emojis
ROBOT="🤖"
RACKET="🚀"
CHECK="✅"
WARNING="⚠️"
ERROR="❌"
GEAR="⚙️"
GLOBE="🌐"
LIGHTNING="⚡"
BRAIN="🧠"

echo -e "${ROBOT} InfoSentinel AI One-Command Deployment"
echo -e "==========================================\n"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is in use
port_in_use() {
    lsof -i :$1 >/dev/null 2>&1
}

# Function to kill process on port
kill_port() {
    local port=$1
    local pid=$(lsof -t -i:$port 2>/dev/null)
    if [ ! -z "$pid" ]; then
        echo -e "${GEAR} Stopping existing service on port $port..."
        kill -9 $pid 2>/dev/null || true
        sleep 1
    fi
}

# AI Environment Check
echo -e "${BRAIN} AI analyzing environment..."

# Check Python
if ! command_exists python3; then
    echo -e "${ERROR} Python3 not found. Please install Python 3.8+"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "ai_automation_engine.py" ]; then
    echo -e "${ERROR} Please run this script from the InfoSentinel project root directory"
    exit 1
fi

echo -e "${CHECK} Environment analysis complete"

# AI Dependency Management
echo -e "\n${GEAR} AI managing dependencies..."

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${GEAR} Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${GEAR} Activating virtual environment..."
source .venv/bin/activate

# Install/upgrade essential packages
echo -e "${GEAR} Installing AI automation dependencies..."
pip install --quiet --upgrade pip
pip install --quiet psutil requests fastapi uvicorn

echo -e "${CHECK} Dependencies ready"

# AI Service Management
echo -e "\n${LIGHTNING} AI starting intelligent service management..."

# Clean up any existing services
echo -e "${GEAR} AI cleaning up existing services..."
kill_port 3000  # React dev server
kill_port 5000  # Backend API
kill_port 5001  # Simple backend
kill_port 8000  # Static server
kill_port 8080  # Alternative static

sleep 2

# Try AI automation engine first
echo -e "\n${ROBOT} Launching AI Automation Engine..."
echo -e "${BRAIN} AI will handle all deployment and monitoring automatically"
echo -e "${LIGHTNING} Self-healing and optimization enabled"
echo -e "${GLOBE} Platform will be available at: http://localhost:8000/public/index-unified.html\n"

# Start AI engine in background and capture its PID
python3 ai_automation_engine.py &
AI_PID=$!

# Wait a moment for AI engine to start
sleep 3

# Check if AI engine is still running
if kill -0 $AI_PID 2>/dev/null; then
    echo -e "${CHECK} AI Automation Engine running (PID: $AI_PID)"
    echo -e "${BRAIN} AI is now managing your InfoSentinel platform"
    echo -e "${GLOBE} Access your platform: ${CYAN}http://localhost:8000/public/index-unified.html${NC}"
    echo -e "\n${ROBOT} AI Features Active:"
    echo -e "   ${CHECK} Automatic service deployment"
    echo -e "   ${CHECK} Intelligent health monitoring"
    echo -e "   ${CHECK} Self-healing capabilities"
    echo -e "   ${CHECK} Performance optimization"
    echo -e "   ${CHECK} Resource management"
    echo -e "\n${YELLOW}Press Ctrl+C to stop all services${NC}\n"
    
    # Wait for AI engine to finish or be interrupted
    wait $AI_PID
else
    echo -e "${WARNING} AI Engine failed to start, falling back to manual deployment..."
    
    # Fallback: Start services manually
    echo -e "\n${GEAR} Starting fallback deployment..."
    
    # Start static frontend (most reliable)
    echo -e "${GEAR} Starting frontend server..."
    cd frontend
    python3 -m http.server 8000 &
    FRONTEND_PID=$!
    cd ..
    
    # Try to start simple backend
    echo -e "${GEAR} Starting backend server..."
    cd backend
    source ../.venv/bin/activate
    python3 simple_app.py &
    BACKEND_PID=$!
    cd ..
    
    sleep 3
    
    echo -e "\n${CHECK} Fallback deployment complete"
    echo -e "${GLOBE} Frontend: ${CYAN}http://localhost:8000/public/index-unified.html${NC}"
    echo -e "${GLOBE} Backend: ${CYAN}http://localhost:5001${NC}"
    echo -e "\n${YELLOW}Press Ctrl+C to stop all services${NC}\n"
    
    # Cleanup function
    cleanup() {
        echo -e "\n${GEAR} Stopping services..."
        kill $FRONTEND_PID 2>/dev/null || true
        kill $BACKEND_PID 2>/dev/null || true
        echo -e "${CHECK} All services stopped"
        exit 0
    }
    
    # Set trap for cleanup
    trap cleanup SIGINT SIGTERM
    
    # Wait for interrupt
    while true; do
        sleep 1
    done
fi

echo -e "\n${CHECK} InfoSentinel AI deployment completed"