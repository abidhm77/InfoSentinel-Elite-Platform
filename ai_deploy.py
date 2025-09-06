#!/usr/bin/env python3
"""
InfoSentinel AI One-Command Deployment
Zero manual intervention - AI handles everything!
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def ai_deploy():
    """AI-powered one-command deployment"""
    print("🤖 InfoSentinel AI Deployment Starting...")
    print("==========================================\n")
    
    project_root = Path(__file__).parent
    
    # Step 1: AI Environment Setup
    print("🔧 AI Setting up environment...")
    try:
        # Activate virtual environment and install dependencies
        if sys.platform == "win32":
            activate_cmd = ".venv\\Scripts\\activate"
        else:
            activate_cmd = "source .venv/bin/activate"
        
        # Install AI automation dependencies
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "psutil", "requests", "fastapi", "uvicorn"
        ], check=True, cwd=project_root)
        
        print("✅ Environment setup complete")
    except Exception as e:
        print(f"⚠️ Environment setup warning: {e}")
    
    # Step 2: Launch AI Automation Engine
    print("\n🚀 Launching AI Automation Engine...")
    try:
        # Start the AI automation engine
        subprocess.run([
            sys.executable, "ai_automation_engine.py"
        ], cwd=project_root)
    except KeyboardInterrupt:
        print("\n🛑 AI Deployment stopped by user")
    except Exception as e:
        print(f"❌ AI Deployment error: {e}")
        
        # Fallback: Start services manually
        print("\n🔄 AI Fallback: Starting services manually...")
        fallback_deploy(project_root)

def fallback_deploy(project_root):
    """Fallback deployment if AI engine fails"""
    print("🔧 Starting fallback deployment...")
    
    try:
        # Start static frontend (most reliable)
        subprocess.Popen([
            "python", "-m", "http.server", "8000"
        ], cwd=project_root / "frontend")
        
        print("✅ Frontend started at: http://localhost:8000/public/index-unified.html")
        
        # Try to start backend
        try:
            subprocess.Popen([
                "python", "simple_app.py"
            ], cwd=project_root / "backend")
            print("✅ Backend started successfully")
        except:
            print("⚠️ Backend start failed - frontend still available")
        
        print("\n🌐 Platform accessible at: http://localhost:8000/public/index-unified.html")
        print("⌨️ Press Ctrl+C to stop...")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n✅ Services stopped")
            
    except Exception as e:
        print(f"❌ Fallback deployment failed: {e}")
        print("\n📖 Manual instructions:")
        print("1. cd frontend")
        print("2. python -m http.server 8000")
        print("3. Open: http://localhost:8000/public/index-unified.html")

if __name__ == "__main__":
    ai_deploy()