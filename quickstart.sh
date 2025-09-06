#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up InfoSentinel Platform...${NC}"

# Install backend dependencies
echo -e "${BLUE}Installing backend dependencies...${NC}"
cd /Users/akokus/Documents/Web-development/Trae/PT/backend
pip install flask flask_cors pymongo python-dotenv requests bcrypt pyjwt

# Install frontend dependencies
echo -e "${BLUE}Installing frontend dependencies...${NC}"
cd /Users/akokus/Documents/Web-development/Trae/PT/frontend
npm install

# Start backend server
echo -e "${GREEN}Starting backend server...${NC}"
cd /Users/akokus/Documents/Web-development/Trae/PT/backend
python app.py &
BACKEND_PID=$!

# Start frontend server
echo -e "${GREEN}Starting frontend server...${NC}"
cd /Users/akokus/Documents/Web-development/Trae/PT/frontend
npm run dev &
FRONTEND_PID=$!

echo -e "${GREEN}InfoSentinel Platform is running!${NC}"
echo -e "${BLUE}Backend: http://localhost:5000${NC}"
echo -e "${BLUE}Frontend: http://localhost:3000${NC}"
echo -e "${RED}Press Ctrl+C to stop both servers${NC}"

# Handle cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT TERM EXIT

# Keep script running
wait