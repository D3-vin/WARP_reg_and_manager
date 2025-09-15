#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mitmproxy process management functionality
"""

import sys
import os
import subprocess
import time
import socket
import psutil
import logging
from PyQt5.QtWidgets import QDialog
from src.managers.certificate_manager import CertificateManager, ManualCertificateDialog
from src.config.languages import _


class MitmProxyManager:
    """Mitmproxy process manager"""

    def __init__(self):
        self.process = None
        self.port = 8080  # Original port
        self.script_path = "src/proxy/warp_proxy_script.py"  # Use actual script
        self.debug_mode = True
        self.cert_manager = CertificateManager()
        self._terminal_opened = False  # Track if terminal window was opened

    def kill_existing_mitmproxy_processes(self):
        """Kill all existing mitmproxy processes to prevent conflicts"""
        try:
            killed_processes = []
            
            # Find all processes with mitmproxy-related names
            for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_info = process.info
                    process_name = process_info['name'].lower() if process_info['name'] else ''
                    cmdline = ' '.join(process_info['cmdline']) if process_info['cmdline'] else ''
                    
                    # Check if process is mitmproxy related
                    is_mitmproxy = (
                        'mitmdump' in process_name or 
                        'mitmproxy' in process_name or
                        'mitmdump' in cmdline or 
                        'mitmproxy' in cmdline or
                        ('python' in process_name and 'warp_proxy_script.py' in cmdline) or
                        ('python' in process_name and str(self.port) in cmdline and 'proxy' in cmdline)
                    )
                    
                    if is_mitmproxy:
                        pid = process_info['pid']
                        logging.info(f"Found existing mitmproxy process: PID {pid}, Name: {process_name}")
                        
                        try:
                            # Try to terminate gracefully first
                            process.terminate()
                            process.wait(timeout=3)
                            killed_processes.append(pid)
                            logging.info(f"Successfully terminated mitmproxy process PID {pid}")
                        except psutil.TimeoutExpired:
                            # Force kill if graceful termination fails
                            process.kill()
                            killed_processes.append(pid)
                            logging.info(f"Force killed mitmproxy process PID {pid}")
                        except psutil.NoSuchProcess:
                            logging.info(f"Process PID {pid} already terminated")
                        except psutil.AccessDenied:
                            logging.warning(f"Access denied when trying to kill process PID {pid}")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Process might have disappeared or we don't have access
                    continue
                    
            if killed_processes:
                logging.info(f"Killed {len(killed_processes)} existing mitmproxy processes: {killed_processes}")
                time.sleep(2)  # Wait for processes to fully terminate
            else:
                logging.info("No existing mitmproxy processes found")
                
            return True
            
        except Exception as e:
            logging.error(f"Error killing existing mitmproxy processes: {e}")
            return False

    def check_port_conflicts(self):
        """Check if port is already in use and try to free it"""
        if self.is_port_open("127.0.0.1", self.port):
            logging.warning(f"Port {self.port} is already in use, attempting to free it...")
            
            try:
                # Find processes using the port
                for conn in psutil.net_connections():
                    if conn.laddr.port == self.port and conn.status == 'LISTEN':
                        try:
                            process = psutil.Process(conn.pid)
                            logging.info(f"Found process using port {self.port}: PID {conn.pid}, Name: {process.name()}")
                            
                            # Kill the process using the port
                            process.terminate()
                            process.wait(timeout=3)
                            logging.info(f"Successfully terminated process PID {conn.pid} using port {self.port}")
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                            logging.warning(f"Could not terminate process PID {conn.pid}: {e}")
                            
                time.sleep(1)  # Wait for port to be freed
                
            except Exception as e:
                logging.error(f"Error checking port conflicts: {e}")
                
        return not self.is_port_open("127.0.0.1", self.port)

    def start(self, parent_window=None):
        """Start Mitmproxy"""
        try:
            # First, kill any existing mitmproxy processes
            logging.info("Checking for existing mitmproxy processes...")
            self.kill_existing_mitmproxy_processes()
            
            # Check and resolve port conflicts
            logging.info(f"Checking port {self.port} availability...")
            if not self.check_port_conflicts():
                logging.warning(f"Port {self.port} is still in use after cleanup attempt")
            
            if self.is_running():
                logging.info("Mitmproxy already running")
                return True

            # First, check if mitmproxy is properly installed
            if not self.check_mitmproxy_installation():
                logging.error("Mitmproxy installation check failed")
                return False

            # On first run, perform certificate check
            if not self.cert_manager.check_certificate_exists():
                logging.info(_('cert_creating'))

                # Run short mitmproxy to create certificate
                temp_cmd = ["mitmdump", "--set", "confdir=~/.mitmproxy", "-q"]
                try:
                    if parent_window:
                        parent_window.status_bar.showMessage(_('cert_creating'), 0)

                    # Platform-specific process creation
                    if sys.platform == "win32":
                        temp_process = subprocess.Popen(temp_cmd, stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        temp_process = subprocess.Popen(temp_cmd, stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)

                    # Wait 5 seconds and terminate process
                    time.sleep(5)
                    temp_process.terminate()
                    temp_process.wait(timeout=3)

                    logging.info("Certificate creation completed")

                except Exception as e:
                    logging.error(f"Certificate creation error: {e}")

                # Check if certificate was created
                if not self.cert_manager.check_certificate_exists():
                    if parent_window:
                        parent_window.status_bar.showMessage(_('cert_creation_failed'), 5000)
                    return False
                else:
                    logging.info(_('cert_created_success'))

            # Automatic certificate installation
            if parent_window and not parent_window.account_manager.is_certificate_approved():
                logging.info(_('cert_installing'))

                # Install certificate automatically
                if self.cert_manager.install_certificate_automatically():
                    # If certificate successfully installed, save approval
                    parent_window.account_manager.set_certificate_approved(True)
                    parent_window.status_bar.showMessage(_('cert_installed_success'), 3000)
                    
                    # On macOS additionally check certificate trust
                    if sys.platform == "darwin":
                        if not self.cert_manager.verify_certificate_trust_macos():
                            logging.warning("Certificate may not be fully trusted. Manual verification recommended.")
                            parent_window.status_bar.showMessage("Certificate installed but may need manual trust setup", 5000)
                else:
                    # Automatic installation failed - show manual installation dialog
                    dialog_result = self.show_manual_certificate_dialog(parent_window)
                    if dialog_result:
                        # User said installation completed
                        parent_window.account_manager.set_certificate_approved(True)
                    else:
                        return False

            # Prepare mitmproxy command - platform-specific with enhanced Windows support
            if sys.platform.startswith('linux'):
                # Linux-specific configuration
                cmd = [
                    "mitmdump",
                    "--listen-host", "127.0.0.1",
                    "-p", str(self.port),
                    "-s", self.script_path,
                    "--set", "confdir=~/.mitmproxy",
                    "--set", "keep_host_header=true",
                    "--set", "ssl_insecure=true",  # Linux: bypass SSL verification issues
                    "--set", "upstream_cert=false",  # Linux: improve compatibility
                ]
                logging.info("Linux Mitmproxy command with additional SSL parameters")
            elif sys.platform == "win32":
                # Enhanced Windows configuration for better interception
                cmd = [
                    "mitmdump",
                    "--listen-host", "0.0.0.0",  # Listen on all interfaces for Windows
                    "-p", str(self.port),
                    "-s", self.script_path,
                    "--set", "confdir=~/.mitmproxy",
                    "--set", "keep_host_header=true",
                    "--set", "ssl_insecure=true",  # Windows: bypass SSL verification
                    "--set", "upstream_cert=false",  # Windows: improve compatibility
                    "--set", "connection_strategy=lazy",  # Windows: improve connection handling
                    "--set", "stream_large_bodies=1m",  # Windows: handle large responses
                    "--set", "body_size_limit=10m",  # Windows: increase body size limit
                    # Removed --ignore-hosts to ensure all requests go through the script
                ]
                logging.info("Windows Mitmproxy command with enhanced Windows-specific parameters")
            else:
                # macOS configuration
                cmd = [
                    "mitmdump",
                    "--listen-host", "127.0.0.1",  # Listen on IPv4
                    "-p", str(self.port),
                    "-s", self.script_path,
                    "--set", "confdir=~/.mitmproxy",
                    "--set", "keep_host_header=true",    # Keep host header
                ]

            logging.info(f"Mitmproxy command: {' '.join(cmd)}")

            # Start process - platform-specific console handling with Windows enhancements
            if sys.platform == "win32":
                cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in cmd)

                if self.debug_mode:
                    # Debug mode: Console window visible with enhanced Windows settings
                    logging.info("Windows Debug mode active - Mitmproxy console window will open")
                    logging.info("Enhanced Windows proxy interception enabled")
                    
                    # Use enhanced Windows command prompt with UTF-8 support
                    self.process = subprocess.Popen(
                        f'start "Mitmproxy Console (Debug) - Enhanced Windows Mode" cmd /k "chcp 65001 && {cmd_str}"',
                        shell=True
                    )
                else:
                    # Normal mode: Hidden console window with Windows optimizations
                    logging.info("Windows Normal mode - Mitmproxy will run in background with enhanced settings")
                    
                    # Set Windows-specific environment variables for better performance
                    env = os.environ.copy()
                    env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output
                    env['MITMPROXY_CERT_DIR'] = os.path.expanduser('~/.mitmproxy')
                    env['PYTHONIOENCODING'] = 'utf-8'  # Handle Unicode properly
                    
                    self.process = subprocess.Popen(
                        cmd_str,
                        shell=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        env=env
                    )

                # Windows enhanced port checking with longer timeout
                logging.info("Starting Mitmproxy with Windows enhancements, checking port...")
                for i in range(15):  # Wait 15 seconds (increased for Windows)
                    time.sleep(1)
                    if self.is_port_open("127.0.0.1", self.port):
                        logging.info(f"Windows: Mitmproxy started successfully - Port {self.port} is open")
                        
                        # Additional Windows verification - proxy is ready
                        time.sleep(2)  # Extra wait for Windows
                        logging.info("Windows: Proxy connection ready")
                        
                        return True
                
                logging.error("Windows: Failed to start Mitmproxy - port did not open in 15 seconds")
                return False
            else:
                # Linux/Mac platform-specific startup
                if sys.platform.startswith('linux'):
                    # Linux-specific process configuration
                    logging.info("Linux: Starting mitmproxy with Linux-specific settings")
                    
                    # Set environment variables for Linux
                    env = os.environ.copy()
                    env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output
                    env['MITMPROXY_CERT_DIR'] = os.path.expanduser('~/.mitmproxy')
                    
                    if self.debug_mode:
                        logging.info("Linux Debug mode: opening terminal window with mitmproxy logs")
                        
                        # Try different terminal emulators for Linux (most common first)
                        terminal_commands = [
                            # GNOME Terminal
                            ['gnome-terminal', '--title=Mitmproxy Console (Debug)', '--', 'bash', '-c', 
                             f"{' '.join(cmd)}; echo '\nℹ️  Mitmproxy finished. Press Enter to close...'; read"],
                            # KDE Konsole
                            ['konsole', '--title', 'Mitmproxy Console (Debug)', '-e', 'bash', '-c', 
                             f"{' '.join(cmd)}; echo '\nℹ️  Mitmproxy finished. Press Enter to close...'; read"],
                            # XFCE Terminal
                            ['xfce4-terminal', '--title=Mitmproxy Console (Debug)', '--command', 'bash', '-c', 
                             f"{' '.join(cmd)}; echo '\nℹ️  Mitmproxy finished. Press Enter to close...'; read"],
                            # Generic xterm
                            ['xterm', '-title', 'Mitmproxy Console (Debug)', '-e', 'bash', '-c', 
                             f"{' '.join(cmd)}; echo '\nℹ️  Mitmproxy finished. Press Enter to close...'; read"],
                            # Terminator
                            ['terminator', '--title=Mitmproxy Console (Debug)', '-x', 'bash', '-c', 
                             f"{' '.join(cmd)}; echo '\nℹ️  Mitmproxy finished. Press Enter to close...'; read"]
                        ]
                        
                        terminal_opened = False
                        for terminal_cmd in terminal_commands:
                            try:
                                # Check if this terminal is available
                                result = subprocess.run(['which', terminal_cmd[0]], 
                                                       capture_output=True, timeout=2)
                                if result.returncode == 0:
                                    logging.info(f"Linux: Opening {terminal_cmd[0]} window...")
                                    self.process = subprocess.Popen(terminal_cmd, env=env)
                                    terminal_opened = True
                                    self._terminal_opened = True  # Flag for process check
                                    break
                            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                                continue
                        
                        if not terminal_opened:
                            logging.warning("Linux: No suitable terminal found - running in background")
                            logging.info("Linux: To display logs install one of:")
                            logging.info("   sudo apt install gnome-terminal (Ubuntu/GNOME)")
                            logging.info("   sudo apt install konsole (KDE)")
                            logging.info("   sudo apt install xfce4-terminal (XFCE)")
                            logging.info("   sudo apt install xterm (Universal)")
                            self._terminal_opened = False  # Reset flag for background mode
                            self.process = subprocess.Popen(
                                cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.STDOUT,
                                text=True, 
                                env=env,
                                bufsize=1,
                                universal_newlines=True
                            )
                    else:
                        logging.info("Linux Normal mode: mitmproxy in background")
                        self._terminal_opened = False  # Reset flag for background mode
                        self.process = subprocess.Popen(
                            cmd, 
                            stdout=subprocess.DEVNULL, 
                            stderr=subprocess.PIPE, 
                            text=True, 
                            env=env
                        )
                        
                elif sys.platform == "darwin":
                    # macOS-specific configuration
                    if self.debug_mode:
                        logging.info("macOS Debug mode: Mitmproxy will run in foreground")
                        logging.info("TLS issues? Run diagnosis with: proxy_manager.diagnose_tls_issues()")
                        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    else:
                        logging.info("macOS Normal mode: Mitmproxy will run in background")
                        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                else:
                    # Fallback for other Unix-like systems
                    if self.debug_mode:
                        logging.info("Debug mode active - Mitmproxy will run in foreground")
                        logging.info("TLS issues? Run diagnosis with: proxy_manager.diagnose_tls_issues()")
                        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    else:
                        logging.info("Normal mode - Mitmproxy will run in background")
                        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                # Wait a bit and check if process is still running
                if sys.platform == "win32":
                    # Windows logic - already handled above
                    pass
                else:
                    # For Linux/macOS, handle terminal vs background differently
                    if sys.platform.startswith('linux') and self.debug_mode and hasattr(self, '_terminal_opened') and self._terminal_opened:
                        # Linux debug mode with terminal - process is actually the terminal wrapper
                        logging.info("Linux Debug: Waiting for startup in opened terminal...")
                        
                        # Wait for port to open (terminal process launches mitmproxy inside)
                        for i in range(10):  # 10 seconds total
                            time.sleep(1)
                            if self.is_port_open("127.0.0.1", self.port):
                                logging.info(f"Linux Debug: Port {self.port} successfully opened in terminal!")
                                logging.info("Mitmproxy started successfully in terminal window")
                                return True
                            
                        logging.warning("Linux Debug: Failed to open port in terminal")
                        logging.info("Linux Debug: Check terminal window with mitmproxy logs")
                        return False
                    else:
                        # Standard process check for background mode or macOS
                        time.sleep(2)
                        
                        if self.process.poll() is None:
                            logging.info(f"Mitmproxy started successfully (PID: {self.process.pid})")
                            
                            # Platform-specific post-start checks
                            if sys.platform.startswith('linux'):
                                logging.debug("Linux: Checking port and process status...")
                                time.sleep(1)
                                if self.is_port_open("127.0.0.1", self.port):
                                    logging.info(f"Linux: Port {self.port} successfully opened")
                                else:
                                    logging.warning(f"Linux: Port {self.port} not responding - additional check...")
                                    time.sleep(3)
                                    if not self.is_port_open("127.0.0.1", self.port):
                                        logging.error("Linux: Failed to open port")
                                        return False
                                        
                            elif sys.platform == "darwin" and self.debug_mode:
                                logging.debug("Running TLS diagnosis (macOS debug mode)...")
                                time.sleep(1)
                                self.diagnose_tls_issues()
                            
                            return True
                        else:
                            # Process terminated, get error output
                            try:
                                stdout, stderr = self.process.communicate(timeout=5)
                                logging.error("Failed to start Mitmproxy - Process terminated")
                                logging.error("Error Details:")
                                if stderr:
                                    logging.error(f"STDERR: {stderr.strip()}")
                                if stdout:
                                    logging.error(f"STDOUT: {stdout.strip()}")
                                
                                self._suggest_mitmproxy_solutions(stderr, stdout)
                            except subprocess.TimeoutExpired:
                                logging.error("Process communication timeout")
                            return False

        except Exception as e:
            logging.error(f"Mitmproxy start error: {e}")
            return False

    def _suggest_mitmproxy_solutions(self, stderr, stdout):
        """Suggest solutions based on mitmproxy error output"""
        print("\n🛠️ Possible Solutions:")
        
        error_text = (stderr or '') + (stdout or '')
        error_lower = error_text.lower()
        
        # Check for common issues
        if 'permission denied' in error_lower or 'operation not permitted' in error_lower:
            print("🔒 Permission Issue:")
            print("   Try running with appropriate permissions")
            print("   Or change to a different port: proxy_manager.port = 8081")
            
        elif 'address already in use' in error_lower or 'port' in error_lower:
            print("🚫 Port Conflict:")
            print("   Another process is using port 8080")
            print("   Kill existing process or use different port")
            print(f"   Check with: lsof -i :8080")
            
        elif 'no module named' in error_lower or 'modulenotfounderror' in error_lower:
            print("📦 Missing Dependencies:")
            print("   Install required packages:")
            print("   pip3 install mitmproxy")
            
        elif 'command not found' in error_lower or 'no such file' in error_lower:
            print("❌ Mitmproxy Not Found:")
            print("   Install mitmproxy:")
            print("   pip3 install mitmproxy")
            print("   Or: brew install mitmproxy")
            
        elif 'certificate' in error_lower or 'ssl' in error_lower or 'tls' in error_lower:
            print("🔒 Certificate Issue:")
            print("   Run certificate diagnosis:")
            print("   proxy_manager.diagnose_tls_issues()")
            
        elif 'script' in error_lower and 'warp_proxy_script' in error_lower:
            print("📜 Script Issue:")
            print("   Check if warp_proxy_script.py exists")
            print("   Verify script has no syntax errors")
            
        else:
            print("🔄 General Troubleshooting:")
            print("1. Check if mitmproxy is installed: mitmdump --version")
            print("2. Try running manually: mitmdump -p 8080")
            print("3. Check system requirements and dependencies")
            print("4. Verify warp_proxy_script.py exists and is valid")
            
        print("\n📞 For more help, check mitmproxy documentation")

    def check_mitmproxy_installation(self):
        """Check if mitmproxy is properly installed"""
        print("\n🔍 MITMPROXY INSTALLATION CHECK")
        print("="*50)
        
        # Check if mitmdump command exists
        try:
            result = subprocess.run(['mitmdump', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ Mitmproxy installed: {result.stdout.strip()}")
            else:
                print(f"❌ Mitmproxy version check failed: {result.stderr}")
                return False
        except FileNotFoundError:
            print("❌ Mitmproxy not found in PATH")
            print("\n📝 Installation commands:")
            print("   pip3 install mitmproxy")
            print("   or: brew install mitmproxy")
            return False
        except subprocess.TimeoutExpired:
            print("❌ Mitmproxy version check timed out")
            return False
            
        # Check if warp_proxy_script.py exists
        if os.path.exists(self.script_path):
            print(f"✅ Proxy script found: {self.script_path}")
        else:
            print(f"❌ Proxy script missing: {self.script_path}")
            return False
            
        # Check port availability
        if not self.is_port_open("127.0.0.1", self.port):
            print(f"✅ Port {self.port} is available")
        else:
            print(f"⚠️ Port {self.port} is already in use")
            print("   Kill the process using this port or choose a different port")
            
        return True

    def stop(self):
        """Stop Mitmproxy - enhanced to stop all instances"""
        try:
            stopped_processes = []
            
            # First try to stop our tracked process
            if self.process and self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                    stopped_processes.append(self.process.pid)
                    logging.info(f"Stopped tracked mitmproxy process (PID: {self.process.pid})")
                except Exception as e:
                    logging.warning(f"Could not stop tracked process: {e}")
                    
            # Then find and stop any other mitmproxy processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_info = proc.info
                    process_name = process_info['name'].lower() if process_info['name'] else ''
                    cmdline = ' '.join(process_info['cmdline']) if process_info['cmdline'] else ''
                    
                    # Check if process is mitmproxy related
                    is_mitmproxy = (
                        'mitmdump' in process_name or 
                        'mitmproxy' in process_name or
                        'mitmdump' in cmdline or 
                        ('python' in process_name and 'warp_proxy_script.py' in cmdline)
                    )
                    
                    if is_mitmproxy and process_info['pid'] not in stopped_processes:
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                            stopped_processes.append(process_info['pid'])
                            logging.info(f"Stopped additional mitmproxy process (PID: {process_info['pid']})")
                        except psutil.TimeoutExpired:
                            # Force kill if graceful termination fails
                            proc.kill()
                            stopped_processes.append(process_info['pid'])
                            logging.info(f"Force killed mitmproxy process (PID: {process_info['pid']})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if stopped_processes:
                logging.info(f"Stopped {len(stopped_processes)} mitmproxy processes: {stopped_processes}")
            else:
                logging.info("No mitmproxy processes found to stop")
                
            # Reset our process reference
            self.process = None
            
            return True
            
        except Exception as e:
            logging.error(f"Mitmproxy stop error: {e}")
            return False

    def is_running(self):
        """Check if Mitmproxy is running"""
        try:
            if self.process and self.process.poll() is None:
                return True

            # Check by PID
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'mitmdump' in proc.info['name'] and str(self.port) in ' '.join(proc.info['cmdline']):
                        return True
                except:
                    continue
            return False
        except:
            return False

    def get_proxy_url(self):
        """Return proxy URL"""
        return f"127.0.0.1:{self.port}"

    def diagnose_tls_issues(self):
        """Diagnose TLS handshake issues and suggest solutions"""
        print("\n" + "🔍" + " TLS HANDSHAKE DIAGNOSIS" + "\n" + "="*50)
        
        # Check certificate existence
        if not self.cert_manager.check_certificate_exists():
            print("❌ Certificate not found")
            print("📝 Solution: Restart mitmproxy to generate certificate")
            return False
        
        print("✅ Certificate file exists")
        
        if sys.platform == "darwin":
            # macOS specific checks
            print("\n🍎 macOS Certificate Trust Check:")
            
            if self.cert_manager.verify_certificate_trust_macos():
                print("✅ Certificate is trusted by system")
            else:
                print("❌ Certificate is NOT trusted by system")
                print("\n🛠️ Attempting automatic fix...")
                
                if self.cert_manager.fix_certificate_trust_macos():
                    print("✅ Automatic fix successful!")
                else:
                    print("❌ Automatic fix failed")
                    print("\n📝 Manual Fix Required:")
                    self.cert_manager._show_manual_certificate_instructions(self.cert_manager.get_certificate_path())
                    return False
        
        # Additional checks
        print("\n🌐 Browser Recommendations:")
        print("1. Chrome: Restart browser after certificate installation")
        print("2. Safari: May require manual certificate approval in Keychain Access")
        print("3. Firefox: Uses its own certificate store - may need separate installation")
        
        return True

    def is_port_open(self, host, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def show_manual_certificate_dialog(self, parent_window):
        """Show manual certificate installation dialog"""
        try:
            dialog = ManualCertificateDialog(self.cert_manager.get_certificate_path(), parent_window)
            return dialog.exec_() == QDialog.Accepted
        except Exception as e:
            logging.error(f"Manual certificate dialog error: {e}")
            return False
    
    def run_enhanced_diagnostics(self):
        """Запуск расширенной диагностики перехвата запросов"""
        print("\n" + "="*60)
        print("🔍 РАСШИРЕННАЯ ДИАГНОСТИКА ПЕРЕХВАТА ЗАПРОСОВ")
        print("="*60)
        
        try:
            # Импортируем и запускаем анализатор
            from src.utils.proxy_debug_analyzer import run_proxy_diagnostics
            from src.utils.windows_proxy_diagnosis import comprehensive_diagnosis
            
            print("\n📊 ЭТАП 1: Анализ прокси-конфигурации")
            print("-" * 40)
            
            # Запускаем анализ прокси
            proxy_analysis = run_proxy_diagnostics()
            
            print("\n📊 ЭТАП 2: Диагностика Windows")
            print("-" * 30)
            
            # Запускаем диагностику Windows
            windows_diagnosis = comprehensive_diagnosis()
            
            print("\n📊 ЭТАП 3: Проверка mitmproxy")
            print("-" * 30)
            
            # Проверяем статус mitmproxy
            print(f"Статус mitmproxy: {'Запущен' if self.is_running() else 'Остановлен'}")
            print(f"Порт: {self.port}")
            print(f"Скрипт: {self.script_path}")
            print(f"Режим отладки: {self.debug_mode}")
            
            # Проверяем доступность порта
            if self.is_port_open("127.0.0.1", self.port):
                print(f"✅ Порт {self.port} доступен")
            else:
                print(f"❌ Порт {self.port} недоступен")
            
            print("\n📊 ЭТАП 4: Рекомендации по устранению")
            print("-" * 35)
            
            # Объединяем рекомендации
            all_recommendations = []
            
            if 'recommendations' in proxy_analysis:
                all_recommendations.extend(proxy_analysis['recommendations'])
            
            # Добавляем специфичные рекомендации
            if not self.is_running():
                all_recommendations.append(
                    "🚨 КРИТИЧНО: mitmproxy не запущен. Нажмите 'Старт Прокси' в главном окне."
                )
            
            if not self.is_port_open("127.0.0.1", self.port):
                all_recommendations.append(
                    f"🚨 КРИТИЧНО: Порт {self.port} заблокирован. "
                    "Проверьте антивирус и брандмауэр."
                )
            
            # Выводим все рекомендации
            for i, recommendation in enumerate(all_recommendations, 1):
                print(f"\n{i}. {recommendation}")
            
            print("\n📋 ДОПОЛНИТЕЛЬНЫЕ ДЕЙСТВИЯ:")
            print("-" * 25)
            print("1. Проверьте файлы логов:")
            print("   - proxy_debug.log (детальные логи прокси)")
            print("   - windows_proxy_diagnosis.json (диагностика Windows)")
            print("   - proxy_analysis_report.json (анализ конфигурации)")
            print("\n2. Если проблема не решена:")
            print("   - Перезапустите приложение от имени администратора")
            print("   - Проверьте исключения в антивирусе")
            print("   - Попробуйте другой порт (8081, 8082)")
            
            print("\n" + "="*60)
            print("✅ ДИАГНОСТИКА ЗАВЕРШЕНА")
            print("="*60)
            
            return {
                'proxy_analysis': proxy_analysis,
                'windows_diagnosis': windows_diagnosis,
                'mitmproxy_status': {
                    'running': self.is_running(),
                    'port_open': self.is_port_open("127.0.0.1", self.port),
                    'port': self.port,
                    'debug_mode': self.debug_mode
                },
                'recommendations': all_recommendations
            }
            
        except Exception as e:
            print(f"❌ Ошибка диагностики: {e}")
            return None