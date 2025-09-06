#!/bin/bash

# Navigate to frontend directory
cd "$(dirname "$0")/frontend"

# Install dependencies
echo "Installing frontend dependencies..."
npm install

# Start the development server
echo "Starting frontend development server..."
npm run dev