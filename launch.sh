#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Launching InfoSentinel Platform...${NC}"

# Install backend dependencies if needed
echo -e "${BLUE}Installing required dependencies...${NC}"
pip install flask flask-cors

# Start backend server
echo -e "${GREEN}Starting backend server...${NC}"
cd /Users/akokus/Documents/Web-development/Trae/PT/backend
python simple_app.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 2

# Open the placeholder page
echo -e "${GREEN}Opening InfoSentinel landing page...${NC}"
open /Users/akokus/Documents/Web-development/Trae/PT/frontend/public/index.html

echo -e "${GREEN}InfoSentinel Platform is running!${NC}"
echo -e "${BLUE}Backend: http://localhost:5000${NC}"
echo -e "${BLUE}Landing Page: Opened in browser${NC}"
echo -e "${RED}Press Ctrl+C to stop the server${NC}"

# Handle cleanup on exit
trap "kill $BACKEND_PID; exit" INT TERM EXIT

# Keep script running
wait