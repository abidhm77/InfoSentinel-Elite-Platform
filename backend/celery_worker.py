#!/usr/bin/env python3
"""
Celery worker startup script for InfoSentinel.
"""
import os
import sys
from celery import Celery
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Celery app
from services.celery_service import celery_app

if __name__ == '__main__':
    # Start the Celery worker
    celery_app.start()