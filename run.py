#!/usr/bin/env python3
import os
import sys
import subprocess
import time
from load_env import load_environment_variables

def main():
    """Main function to run the secure communication application"""
    # Load environment variables
    load_environment_variables()
    
    # Set the server port
    server_port = int(os.getenv('SERVER_PORT', 12000))
    websocket_port = int(os.getenv('WEBSOCKET_PORT', 8765))
    
    print(f"Starting server on port {server_port} and WebSocket on port {websocket_port}")
    
    # Start the server in a separate process
    server_process = subprocess.Popen(
        [sys.executable, "secure-comm-app/server.py"],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    
    # Wait for the server to start
    print("Waiting for server to start...")
    time.sleep(2)
    
    try:
        # Start the main application
        print("Starting main application...")
        main_process = subprocess.Popen(
            [sys.executable, "secure-comm-app/main.py"],
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        # Wait for the main process to finish
        main_process.wait()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        # Terminate the server process
        if server_process.poll() is None:
            server_process.terminate()
            print("Server terminated")

if __name__ == "__main__":
    main()