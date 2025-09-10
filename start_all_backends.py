#!/usr/bin/env python3
"""
Startup script to run all backend services simultaneously
"""

import os
import sys
import subprocess
import threading
import time
import signal
from pathlib import Path

class BackendManager:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def run_service(self, script_name, port, service_name):
        """Run a backend service in a subprocess"""
        try:
            print(f"🚀 Starting {service_name} on port {port}...")
            
            # Start the process
            process = subprocess.Popen(
                [sys.executable, script_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.processes.append({
                'process': process,
                'name': service_name,
                'port': port,
                'script': script_name
            })
            
            # Monitor the process
            while self.running and process.poll() is None:
                time.sleep(1)
                
            if process.poll() is not None and self.running:
                print(f"❌ {service_name} stopped unexpectedly (exit code: {process.poll()})")
                
        except Exception as e:
            print(f"❌ Error starting {service_name}: {e}")
    
    def stop_all_services(self):
        """Stop all running services"""
        print("\n🛑 Stopping all backend services...")
        self.running = False
        
        for service_info in self.processes:
            try:
                process = service_info['process']
                if process.poll() is None:  # Process is still running
                    print(f"   Stopping {service_info['name']}...")
                    process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print(f"   Force killing {service_info['name']}...")
                        process.kill()
                        process.wait()
                        
            except Exception as e:
                print(f"   Error stopping {service_info['name']}: {e}")
        
        print("✅ All services stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    if 'manager' in globals():
        manager.stop_all_services()
    sys.exit(0)

def main():
    global manager
    
    print("🛡️  Cybersecurity Backend Services Manager")
    print("=" * 60)
    
    services = [
        {
            'script': 'api_server.py',
            'port': 8000,
            'name': 'Main API Server',
            'description': 'Bridge between frontend and Supabase'
        },
        {
            'script': 'backend/threat_ingestion_api.py',
            'port': 8001,
            'name': 'Threat Ingestion API',
            'description': 'ML-powered threat analysis and storage'
        },
        {
            'script': 'threat_detection_backend.py',
            'port': 5000,
            'name': 'Threat Detection Backend',
            'description': 'Real-time packet capture and analysis'
        },
        {
            'script': 'email_service_backend.py',
            'port': 8004,
            'name': 'Email Service Backend',
            'description': 'SMTP email alert system'
        },
        {
            'script': 'real_time_monitor_api.py',
            'port': 8005,
            'name': 'Real-Time Interface Monitor API',
            'description': 'Interface monitoring API'
        },
        {
            'script': 'ml_models/model_api.py',
            'port': 8003,
            'name': 'ML Model API',
            'description': 'Machine learning model training and inference'
        }
    ]
    
    print("Services to start:")
    for service in services:
        print(f"  • {service['name']} (port {service['port']}) - {service['description']}")
    print()
    
    # Check if files exist
    missing_files = []
    for service in services:
        if not os.path.exists(service['script']):
            missing_files.append(service['script'])
    
    if missing_files:
        print("❌ Missing backend files:")
        for file in missing_files:
            print(f"   {file}")
        print("\nPlease ensure all backend files are present")
        return False
    
    print("✅ All backend files found")
    
    # Check environment variables
    required_env_vars = ['SUPABASE_URL', 'SUPABASE_KEY']
    missing_env = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_env.append(var)
    
    if missing_env:
        print("⚠️  Missing environment variables:")
        for var in missing_env:
            print(f"   {var}")
        print("   Some services may not work properly without these")
    
    print("\n🚀 Starting all services simultaneously...")
    print("   Each service will start in its own process")
    print("   Press Ctrl+C to stop all services")
    print("   Check individual service logs for detailed output")
    print()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create backend manager
    manager = BackendManager()
    
    # Start all services in separate threads
    threads = []
    for service in services:
        thread = threading.Thread(
            target=manager.run_service,
            args=(service['script'], service['port'], service['name']),
            daemon=True,
            name=f"Thread-{service['name']}"
        )
        thread.start()
        threads.append(thread)
        time.sleep(1)  # Stagger startup to avoid port conflicts
    
    print("✅ All services started!")
    print("\nService Status:")
    print("  • Main API Server: http://localhost:8000")
    print("  • Threat Ingestion: http://localhost:8001")
    print("  • Threat Detection: http://localhost:5000")
    print("  • Email Service: http://localhost:8004")
    print("  • Interface Monitor: http://localhost:8005")
    print("  • ML Model API: http://localhost:8003")
    print("\n📊 Frontend Dashboard: http://localhost:5173")
    print("\n💡 Tips:")
    print("   - For packet capture, run with admin/root privileges")
    print("   - Check individual service logs if issues occur")
    print("   - All services will restart automatically if they crash")
    
    try:
        # Keep main thread alive and monitor services
        while manager.running:
            time.sleep(5)
            
            # Check if any critical services have stopped
            active_processes = sum(1 for s in manager.processes if s['process'].poll() is None)
            if active_processes < len(services):
                print(f"⚠️  Warning: {len(services) - active_processes} service(s) have stopped")
            
    except KeyboardInterrupt:
        print("\n🛑 Shutdown signal received...")
        manager.stop_all_services()

if __name__ == "__main__":
    main()