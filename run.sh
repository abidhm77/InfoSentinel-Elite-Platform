#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting World-Class Automated Penetration Testing Platform...${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3 to run the backend."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js is not installed. Please install Node.js to run the frontend."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "npm is not installed. Please install npm to run the frontend."
    exit 1
fi

# Create Python virtual environment if it doesn't exist
if [ ! -d "backend/venv" ]; then
    echo -e "${GREEN}Creating Python virtual environment...${NC}"
    cd backend
    python3 -m venv venv
    cd ..
fi

# Install backend dependencies
echo -e "${GREEN}Installing backend dependencies...${NC}"
cd backend
source venv/bin/activate
pip install -r requirements.txt

# Start backend server in the background
echo -e "${GREEN}Starting backend server...${NC}"
python app.py &
BACKEND_PID=$!
cd ..

# Install frontend dependencies
echo -e "${GREEN}Installing frontend dependencies...${NC}"
cd frontend
npm install

# Start frontend development server
echo -e "${GREEN}Starting frontend development server...${NC}"
npm run dev &
FRONTEND_PID=$!
cd ..

echo -e "${BLUE}Both servers are running!${NC}"
echo -e "${GREEN}Frontend:${NC} http://localhost:3000"
echo -e "${GREEN}Backend API:${NC} http://localhost:5000"
echo -e "${BLUE}Press Ctrl+C to stop both servers${NC}"

# Function to kill processes on exit
function cleanup {
    echo -e "${BLUE}Stopping servers...${NC}"
    kill $BACKEND_PID
    kill $FRONTEND_PID
    echo -e "${BLUE}Servers stopped.${NC}"
}

# Register the cleanup function to be called on exit
trap cleanup EXIT

# Wait for user to press Ctrl+C
wait