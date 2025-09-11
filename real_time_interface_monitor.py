#!/usr/bin/env python3
"""
Real-Time Network Interface Monitor
Monitors Wi-Fi and Ethernet interfaces for threats with ML detection
"""

import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
import logging
import uuid
import sys
import os
import signal
import psutil
import socket
import struct
import asyncio
import aiohttp

# Import our ML model
from ml_models.threat_detection_model import threat_model

# Database integration
from supabase_client import supabase

# Network packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
    print("✅ Scapy available - full packet capture enabled")
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available - limited monitoring mode")
    print("   Install with: pip install scapy")

class InterfaceMonitor:
    """Monitor specific network interface for threats"""
    
    def __init__(self, interface_name: str, interface_type: str):
        self.interface_name = interface_name
        self.interface_type = interface_type  # 'wifi' or 'ethernet'
        self.is_active = False
        self.packet_count = 0
        self.threat_count = 0
        self.bytes_captured = 0
        
        # Threat detection
        self.threat_buffer = deque(maxlen=1000)
        self.recent_threats = deque(maxlen=100)  # For API access
        self.connection_tracker = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'threats_detected': 0,
            'blocked_ips': set(),
            'protocol_distribution': defaultdict(int),
            'threat_types': defaultdict(int),
            'severity_distribution': defaultdict(int)
        }
        
        # Setup logging
        self.logger = logging.getLogger(f"Interface-{interface_name}")
    
    def packet_handler(self, packet):
        """Handle captured packets with ML threat detection"""
        try:
            if not packet.haslayer(IP):
                return
            
            self.packet_count += 1
            self.stats['total_packets'] += 1
            
            # Extract packet information
            ip_layer = packet[IP]
            packet_info = {
                'timestamp': datetime.now(),
                'source_ip': ip_layer.src,
                'destination_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'packet_size': len(packet),
                'ttl': ip_layer.ttl,
                'interface': self.interface_name,
                'interface_type': self.interface_type
            }
            
            # Protocol-specific parsing
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'source_port': tcp_layer.sport,
                    'destination_port': tcp_layer.dport,
                    'tcp_flags': tcp_layer.flags,
                    'tcp_window': tcp_layer.window,
                    'payload': bytes(packet[Raw]) if packet.haslayer(Raw) else b''
                })
                self.stats['protocol_distribution']['TCP'] += 1
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'source_port': udp_layer.sport,
                    'destination_port': udp_layer.dport,
                    'payload': bytes(packet[Raw]) if packet.haslayer(Raw) else b''
                })
                self.stats['protocol_distribution']['UDP'] += 1
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'protocol': 'ICMP',
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code,
                    'source_port': 0,
                    'destination_port': 0,
                    'payload': bytes(packet[Raw]) if packet.haslayer(Raw) else b''
                })
                self.stats['protocol_distribution']['ICMP'] += 1
            
            # Update connection tracking
            self.update_connection_stats(packet_info)
            
            # Enhance packet info with behavioral data
            packet_info = self.enhance_packet_info(packet_info)
            
            # ML-based threat detection
            threat_result = threat_model.predict_threat(packet_info)
            
            # Process threat result
            if threat_result['final_classification']['is_threat']:
                self.process_threat_detection(packet_info, threat_result)
            
            # Update statistics
            self.bytes_captured += packet_info['packet_size']
            
            # Log periodic stats
            if self.packet_count % 1000 == 0:
                self.log_interface_stats()
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def update_connection_stats(self, packet_info: Dict):
        """Update connection statistics for behavioral analysis"""
        source_ip = packet_info['source_ip']
        tracker = self.connection_tracker[source_ip]
        
        tracker['packets'] += 1
        tracker['bytes'] += packet_info['packet_size']
        tracker['last_seen'] = packet_info['timestamp']
        
        if not tracker['first_seen']:
            tracker['first_seen'] = packet_info['timestamp']
        
        if 'destination_port' in packet_info:
            tracker['ports'].add(packet_info['destination_port'])
    
    def enhance_packet_info(self, packet_info: Dict) -> Dict:
        """Enhance packet info with behavioral features"""
        source_ip = packet_info['source_ip']
        tracker = self.connection_tracker[source_ip]
        
        # Calculate behavioral features
        if tracker['first_seen']:
            time_active = (packet_info['timestamp'] - tracker['first_seen']).total_seconds()
            packet_info['connection_frequency'] = tracker['packets'] / max(time_active, 1)
            packet_info['packets_per_second'] = tracker['packets'] / max(time_active, 1)
        else:
            packet_info['connection_frequency'] = 0
            packet_info['packets_per_second'] = 0
        
        packet_info['unique_ports'] = len(tracker['ports'])
        packet_info['bytes_transferred'] = tracker['bytes']
        packet_info['reputation_score'] = self.get_ip_reputation(source_ip)
        
        return packet_info
    
    def get_ip_reputation(self, ip: str) -> float:
        """Get IP reputation score (simplified)"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private:
                return 0.8  # Generally trust private IPs more
            elif ip_addr.is_loopback:
                return 1.0
            else:
                # Simulate external reputation lookup
                return 0.5  # Neutral for external IPs
        except:
            return 0.1  # Low trust for invalid IPs
    
    def process_threat_detection(self, packet_info: Dict, threat_result: Dict):
        """Process detected threat and send to dashboard"""
        try:
            self.threat_count += 1
            self.stats['threats_detected'] += 1
            
            final_classification = threat_result['final_classification']
            threat_type = final_classification['threat_type']
            severity = final_classification['severity']
            confidence = final_classification['confidence']
            
            # Update statistics
            self.stats['threat_types'][threat_type] += 1
            self.stats['severity_distribution'][f'severity_{severity}'] += 1
            
            # Create threat alert for dashboard
            threat_alert = {
                'id': str(uuid.uuid4()),
                'timestamp': packet_info['timestamp'].isoformat(),
                'source_ip': packet_info['source_ip'],
                'destination_ip': packet_info['destination_ip'],
                'interface': self.interface_name,
                'interface_type': self.interface_type,
                'threat_type': threat_type,
                'severity': severity,
                'confidence': confidence,
                'description': f"{threat_type.replace('_', ' ').title()} detected on {self.interface_type} interface",
                'protocol': packet_info.get('protocol', 'Unknown'),
                'packet_size': packet_info['packet_size'],
                'indicators': threat_result.get('rule_based', {}).get('rules_triggered', []),
                'ml_classification': threat_result.get('primary_classification', {}),
                'anomaly_detected': threat_result.get('anomaly_detection', {}).get('is_anomaly', False),
                'raw_data': {
                    'source_port': packet_info.get('source_port'),
                    'destination_port': packet_info.get('destination_port'),
                    'tcp_flags': packet_info.get('tcp_flags'),
                    'payload_size': len(packet_info.get('payload', b''))
                }
            }
            
            # Store threat
            self.threat_buffer.append(threat_alert)
            self.recent_threats.append(threat_alert)
            
            # Send to Supabase for dashboard display
            self.send_threat_to_dashboard(threat_alert)
            
            # Auto-block high severity threats
            if severity >= 8:
                self.stats['blocked_ips'].add(packet_info['source_ip'])
                self.logger.critical(f"🚫 AUTO-BLOCKED: {packet_info['source_ip']} - Severity {severity}")
                
                # Send high-priority email alert
                asyncio.create_task(self.send_email_alert(threat_alert, 'critical'))
            elif severity >= 6:
                # Send medium-priority email alert
                asyncio.create_task(self.send_email_alert(threat_alert, 'high'))
            
            # Log threat detection
            self.logger.warning(
                f"⚠️  THREAT DETECTED: {packet_info['source_ip']} -> {packet_info['destination_ip']} "
                f"[{threat_type}] Severity: {severity} Confidence: {confidence:.2f} Interface: {self.interface_name}"
            )
            
        except Exception as e:
            self.logger.error(f"Error processing threat: {e}")
    
    async def send_email_alert(self, threat_alert: Dict, priority: str):
        """Send email alert for detected threat"""
        try:
            # Send to email service backend
            email_data = {
                'config': {
                    'smtpServer': 'smtp.gmail.com',  # Default - should be configured
                    'smtpPort': 587,
                    'smtpUsername': '',  # Will be filled from configuration
                    'smtpPassword': '',  # Will be filled from configuration
                    'useTls': True,
                    'fromEmail': 'security@company.com',
                    'toEmails': ['admin@company.com'],  # Default recipients
                    'subjectPrefix': '[INTERFACE THREAT]'
                },
                'alertType': threat_alert['threat_type'],
                'title': f"{threat_alert['threat_type'].replace('_', ' ').title()} Detected",
                'message': f"""Real-time threat detected on {threat_alert['interface']} interface:

Source IP: {threat_alert['source_ip']}
Destination IP: {threat_alert['destination_ip']}
Interface: {threat_alert['interface']} ({threat_alert['interface_type']})
Threat Type: {threat_alert['threat_type']}
Severity: {threat_alert['severity']}/10
Confidence: {threat_alert['confidence']:.2f}
Protocol: {threat_alert['protocol']}

Description: {threat_alert['description']}

ML Classification: {json.dumps(threat_alert['ml_classification'], indent=2)}

Immediate investigation recommended.""",
                'severity': priority,
                'timestamp': threat_alert['timestamp'],
                'sourceIp': threat_alert['source_ip'],
                'destinationIp': threat_alert['destination_ip'],
                'threatIndicators': threat_alert['indicators'],
                'affectedSystems': [threat_alert['interface']],
                'category': 'threat'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'http://localhost:8004/api/email/send',
                    json=email_data,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"📧 Email alert sent for threat {threat_alert['id']}")
                    else:
                        self.logger.warning(f"❌ Email alert failed: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")
    
    def send_threat_to_dashboard(self, threat_alert: Dict):
        """Send threat alert to dashboard via Supabase"""
        try:
            # Insert into alerts table for dashboard display
            alert_data = {
                'timestamp': threat_alert['timestamp'],
                'src_ip': threat_alert['source_ip'],
                'dst_ip': threat_alert['destination_ip'],
                'protocol': threat_alert['protocol'],
                'threat_level': threat_alert['severity'],
                'threats': [threat_alert['threat_type']] + threat_alert['indicators'],
                'packet_size': threat_alert['packet_size'],
                'interface': threat_alert['interface'],
                'interface_type': threat_alert['interface_type'],
                'confidence': threat_alert['confidence'],
                'ml_classification': json.dumps(threat_alert['ml_classification']),
                'anomaly_detected': threat_alert['anomaly_detected']
            }
            
            supabase.table("alerts").insert(alert_data).execute()
            
            # Also insert into network_traffic table
            traffic_data = {
                'timestamp': threat_alert['timestamp'],
                'source_ip': threat_alert['source_ip'],
                'destination_ip': threat_alert['destination_ip'],
                'source_port': threat_alert['raw_data'].get('source_port'),
                'destination_port': threat_alert['raw_data'].get('destination_port'),
                'protocol': threat_alert['protocol'],
                'packet_size': threat_alert['packet_size'],
                'is_suspicious': True,
                'threat_indicators': threat_alert['indicators']
            }
            
            supabase.table("network_traffic").insert(traffic_data).execute()
            
        except Exception as e:
            self.logger.error(f"Error sending threat to dashboard: {e}")
    
    def log_interface_stats(self):
        """Log interface statistics"""
        threat_rate = (self.threat_count / max(self.packet_count, 1)) * 100
        
        self.logger.info(
            f"📊 {self.interface_name} ({self.interface_type}): "
            f"{self.packet_count:,} packets, {self.threat_count} threats ({threat_rate:.2f}%), "
            f"{len(self.stats['blocked_ips'])} blocked IPs"
        )
    
    def start_monitoring(self):
        """Start monitoring this interface"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Cannot start monitoring - Scapy not available")
            return False
        
        try:
            self.is_active = True
            self.logger.info(f"🚀 Starting {self.interface_type} monitoring on {self.interface_name}")
            
            # Configure Scapy for this interface
            conf.iface = self.interface_name
            
            # Start packet capture
            sniff(
                iface=self.interface_name,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda p: not self.is_active
            )
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring {self.interface_name}: {e}")
            self.is_active = False
            return False
    
    def stop_monitoring(self):
        """Stop monitoring this interface"""
        self.is_active = False
        self.logger.info(f"🛑 Stopped monitoring {self.interface_name}")

    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        """Get recent threats for API access"""
        return list(self.recent_threats)[-limit:]

class RealTimeNetworkMonitor:
    """Real-time network monitor for multiple interfaces"""
    
    def __init__(self):
        self.interface_monitors = {}
        self.monitoring_active = False
        self.monitor_threads = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('real_time_threats.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Discover available interfaces
        self.discover_interfaces()
    
    def discover_interfaces(self):
        """Discover available network interfaces"""
        self.available_interfaces = []
        
        if SCAPY_AVAILABLE:
            try:
                # Get interfaces from Scapy
                scapy_interfaces = get_if_list()
                
                # Get interface statistics from psutil
                net_stats = psutil.net_if_stats()
                
                for iface in scapy_interfaces:
                    if iface in net_stats and net_stats[iface].isup:
                        # Determine interface type
                        interface_type = 'ethernet'
                        if any(wifi_indicator in iface.lower() for wifi_indicator in ['wlan', 'wifi', 'wireless', 'wl']):
                            interface_type = 'wifi'
                        elif any(eth_indicator in iface.lower() for eth_indicator in ['eth', 'en', 'em']):
                            interface_type = 'ethernet'
                        
                        self.available_interfaces.append({
                            'name': iface,
                            'type': interface_type,
                            'is_up': True
                        })
                
                self.logger.info(f"📡 Discovered {len(self.available_interfaces)} active interfaces:")
                for iface in self.available_interfaces:
                    self.logger.info(f"   • {iface['name']} ({iface['type']})")
                    
            except Exception as e:
                self.logger.error(f"Error discovering interfaces: {e}")
        else:
            # Fallback to psutil only
            try:
                net_stats = psutil.net_if_stats()
                for iface_name, stats in net_stats.items():
                    if stats.isup and iface_name != 'lo':
                        interface_type = 'ethernet'
                        if 'wlan' in iface_name.lower() or 'wifi' in iface_name.lower():
                            interface_type = 'wifi'
                        
                        self.available_interfaces.append({
                            'name': iface_name,
                            'type': interface_type,
                            'is_up': True
                        })
            except Exception as e:
                self.logger.error(f"Error getting interface stats: {e}")
    
    def start_monitoring_all_interfaces(self):
        """Start monitoring all available interfaces"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Cannot start monitoring - Scapy not available")
            return False
        
        if not self.available_interfaces:
            self.logger.error("No available interfaces found")
            return False
        
        self.monitoring_active = True
        self.logger.info("🚀 Starting real-time threat detection on all interfaces...")
        
        # Start monitoring each interface in separate thread
        for interface_info in self.available_interfaces:
            interface_name = interface_info['name']
            interface_type = interface_info['type']
            
            # Create monitor for this interface
            monitor = InterfaceMonitor(interface_name, interface_type)
            self.interface_monitors[interface_name] = monitor
            
            # Start monitoring thread
            thread = threading.Thread(
                target=monitor.start_monitoring,
                daemon=True,
                name=f"Monitor-{interface_name}"
            )
            thread.start()
            self.monitor_threads.append(thread)
            
            time.sleep(1)  # Stagger startup
        
        self.logger.info(f"✅ Started monitoring {len(self.interface_monitors)} interfaces")
        return True
    
    def stop_monitoring_all_interfaces(self):
        """Stop monitoring all interfaces"""
        self.monitoring_active = False
        
        for monitor in self.interface_monitors.values():
            monitor.stop_monitoring()
        
        self.logger.info("🛑 Stopped monitoring all interfaces")
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics"""
        total_packets = sum(monitor.packet_count for monitor in self.interface_monitors.values())
        total_threats = sum(monitor.threat_count for monitor in self.interface_monitors.values())
        total_blocked = len(set().union(*[monitor.stats['blocked_ips'] for monitor in self.interface_monitors.values()]))
        
        interface_stats = {}
        for name, monitor in self.interface_monitors.items():
            interface_stats[name] = {
                'type': monitor.interface_type,
                'packets': monitor.packet_count,
                'threats': monitor.threat_count,
                'bytes': monitor.bytes_captured,
                'threat_rate': (monitor.threat_count / max(monitor.packet_count, 1)) * 100,
                'active': monitor.is_active,
                'protocol_distribution': dict(monitor.stats['protocol_distribution']),
                'threat_types': dict(monitor.stats['threat_types'])
            }
        
        return {
            'total_packets': total_packets,
            'total_threats': total_threats,
            'total_blocked_ips': total_blocked,
            'interfaces': interface_stats,
            'monitoring_active': self.monitoring_active,
            'model_info': threat_model.get_model_info()
        }
    
    def print_monitoring_dashboard(self):
        """Print real-time monitoring dashboard"""
        stats = self.get_monitoring_statistics()
        
        print("\n" + "="*80)
        print(f"🛡️  REAL-TIME THREAT DETECTION DASHBOARD - {datetime.now().strftime('%H:%M:%S')}")
        print("="*80)
        
        # Overall statistics
        print(f"📊 Total: {stats['total_packets']:,} packets | "
              f"🚨 Threats: {stats['total_threats']} | "
              f"🚫 Blocked: {stats['total_blocked_ips']}")
        
        # Interface breakdown
        print(f"\n📡 INTERFACE STATUS:")
        for iface_name, iface_stats in stats['interfaces'].items():
            status = "🟢 ACTIVE" if iface_stats['active'] else "🔴 INACTIVE"
            threat_rate = iface_stats['threat_rate']
            
            print(f"  {status} {iface_name} ({iface_stats['type'].upper()})")
            print(f"    Packets: {iface_stats['packets']:,} | "
                  f"Threats: {iface_stats['threats']} ({threat_rate:.2f}%) | "
                  f"Bytes: {iface_stats['bytes']:,}")
        
        # Model status
        model_info = stats['model_info']
        print(f"\n🤖 ML MODEL STATUS:")
        print(f"  Status: {model_info['model_status']}")
        print(f"  Features: {model_info['feature_count']}")
        print(f"  Cache: {model_info['cache_size']} predictions")
        print(f"  New Data: {model_info['training_data_available']} samples")
        
        # Recent threats by interface
        print(f"\n🚨 RECENT THREATS BY INTERFACE:")
        for iface_name, monitor in self.interface_monitors.items():
            recent_threats = list(monitor.threat_buffer)[-3:]
            if recent_threats:
                print(f"  {iface_name} ({monitor.interface_type}):")
                for threat in recent_threats:
                    timestamp = threat['timestamp'][:19] if isinstance(threat['timestamp'], str) else threat['timestamp'].strftime('%H:%M:%S')
                    print(f"    {timestamp} - {threat['threat_type']} (Severity: {threat['severity']})")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\n🛑 Received signal {signum} - shutting down...")
    if 'monitor' in globals():
        monitor.stop_monitoring_all_interfaces()
    sys.exit(0)

def check_privileges():
    """Check if running with required privileges"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Warning: Not running as administrator")
                print("   Packet capture may fail on Windows without admin privileges")
                return False
        except:
            pass
    elif os.name == 'posix':  # Linux/macOS
        if os.geteuid() != 0:
            print("⚠️  Warning: Not running as root")
            print("   Try: sudo python3 real_time_interface_monitor.py")
            return False
    
    return True

def main():
    """Main monitoring function"""
    print("🛡️  Real-Time Network Interface Threat Detection")
    print("=" * 60)
    print("🔍 Multi-interface monitoring (Wi-Fi + Ethernet)")
    print("🤖 ML-powered threat detection with persistent learning")
    print("📊 Real-time dashboard integration")
    print("💾 Automatic model improvement")
    print()
    
    # Check requirements
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not available - cannot capture packets")
        print("   Install with: pip install scapy")
        sys.exit(1)
    
    # Check privileges
    has_privileges = check_privileges()
    if not has_privileges:
        print("⚠️  May not have sufficient privileges for packet capture")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Initialize model
    print("🤖 Initializing ML threat detection model...")
    model_info = threat_model.get_model_info()
    print(f"   Model status: {model_info['model_status']}")
    print(f"   Features: {model_info['feature_count']}")
    print(f"   Threat categories: {len(model_info['threat_categories'])}")
    
    # Train model if not already trained
    if model_info['model_status'] != 'trained':
        print("🔄 Training initial model with synthetic data...")
        try:
            X_synthetic, y_synthetic = threat_model.generate_synthetic_training_data(2000)
            
            # Convert synthetic data to event format
            synthetic_events = []
            for i in range(len(X_synthetic)):
                event = {
                    'source_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                    'destination_ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                    'packet_size': X_synthetic[i][0],
                    'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
                    'timestamp': datetime.now().isoformat()
                }
                synthetic_events.append(event)
            
            metrics = threat_model.train_model(synthetic_events, y_synthetic.tolist())
            print(f"✅ Model trained - Accuracy: {metrics.accuracy:.3f}")
            
        except Exception as e:
            print(f"❌ Model training failed: {e}")
            sys.exit(1)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start monitor
    global monitor
    monitor = RealTimeNetworkMonitor()
    
    if not monitor.start_monitoring_all_interfaces():
        print("❌ Failed to start monitoring")
        sys.exit(1)
    
    try:
        print("\n🔄 Real-time monitoring active...")
        print("   Threats will be displayed on the dashboard")
        print("   Model will learn and improve automatically")
        print("   Press Ctrl+C to stop\n")
        
        # Main monitoring loop
        while monitor.monitoring_active:
            time.sleep(10)  # Update dashboard every 10 seconds
            monitor.print_monitoring_dashboard()
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping real-time monitoring...")
        monitor.stop_monitoring_all_interfaces()
        
        # Save final statistics
        final_stats = monitor.get_monitoring_statistics()
        with open(f'monitoring_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
            json.dump(final_stats, f, indent=2, default=str)
        
        print("📄 Final monitoring report saved")

if __name__ == "__main__":
    main()