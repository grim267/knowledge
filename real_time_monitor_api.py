#!/usr/bin/env python3
"""
Real-Time Monitor API
REST API for the real-time interface monitoring system
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import json
from datetime import datetime
import logging
import sys
import os

# Import the real-time monitor
try:
    from real_time_interface_monitor import RealTimeNetworkMonitor
    MONITOR_AVAILABLE = True
except ImportError:
    MONITOR_AVAILABLE = False
    print("⚠️  Real-time monitor not available")

app = Flask(__name__)
CORS(app)

# Global monitor instance
network_monitor = None
monitor_thread = None
monitoring_active = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'monitor_available': MONITOR_AVAILABLE,
        'monitoring_active': monitoring_active,
        'scapy_available': MONITOR_AVAILABLE
    })

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    if not MONITOR_AVAILABLE:
        return jsonify({'error': 'Monitor not available'}), 500
    
    try:
        if network_monitor:
            interfaces = []
            for iface_info in network_monitor.available_interfaces:
                interfaces.append({
                    'name': iface_info['name'],
                    'type': iface_info['type'],
                    'is_up': iface_info['is_up']
                })
            return jsonify({'interfaces': interfaces})
        else:
            return jsonify({'interfaces': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_monitoring_stats():
    """Get monitoring statistics"""
    if not network_monitor:
        return jsonify({
            'total_packets': 0,
            'total_threats': 0,
            'total_blocked_ips': 0,
            'interfaces': {},
            'monitoring_active': False,
            'model_info': {
                'model_status': 'not_loaded',
                'feature_count': 0,
                'cache_size': 0,
                'training_data_available': 0
            }
        })
    
    try:
        stats = network_monitor.get_monitoring_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent', methods=['GET'])
def get_recent_threats():
    """Get recent threats from all interfaces"""
    limit = request.args.get('limit', 50, type=int)
    
    if not network_monitor:
        return jsonify({'threats': []})
    
    try:
        all_threats = []
        
        # Collect threats from all interface monitors
        for monitor in network_monitor.interface_monitors.values():
            for threat in list(monitor.threat_buffer)[-limit:]:
                all_threats.append(threat)
        
        # Sort by timestamp (most recent first)
        all_threats.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'threats': all_threats[:limit],
            'total': len(all_threats)
        })
        
    except Exception as e:
        logger.error(f"Error getting recent threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring"""
    global network_monitor, monitor_thread, monitoring_active
    
    if not MONITOR_AVAILABLE:
        return jsonify({'error': 'Monitor not available - install scapy'}), 500
    
    if monitoring_active:
        return jsonify({'message': 'Monitoring already active'})
    
    try:
        # Initialize monitor if not exists
        if not network_monitor:
            network_monitor = RealTimeNetworkMonitor()
        
        # Start monitoring in background thread
        def start_monitoring_thread():
            global monitoring_active
            try:
                monitoring_active = True
                network_monitor.start_monitoring_all_interfaces()
            except Exception as e:
                logger.error(f"Monitoring thread error: {e}")
                monitoring_active = False
        
        monitor_thread = threading.Thread(target=start_monitoring_thread, daemon=True)
        monitor_thread.start()
        
        logger.info("🚀 Real-time monitoring started")
        return jsonify({
            'status': 'success',
            'message': 'Real-time monitoring started',
            'interfaces': len(network_monitor.available_interfaces)
        })
        
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring"""
    global monitoring_active
    
    if not monitoring_active:
        return jsonify({'message': 'Monitoring not active'})
    
    try:
        monitoring_active = False
        if network_monitor:
            network_monitor.stop_monitoring_all_interfaces()
        
        logger.info("🛑 Real-time monitoring stopped")
        return jsonify({
            'status': 'success',
            'message': 'Real-time monitoring stopped'
        })
        
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Block an IP address"""
    try:
        if network_monitor:
            # Add to blocked IPs for all interface monitors
            for monitor in network_monitor.interface_monitors.values():
                monitor.stats['blocked_ips'].add(ip)
            
            logger.info(f"🚫 Manually blocked IP: {ip}")
            return jsonify({
                'status': 'success',
                'message': f'IP {ip} blocked on all interfaces'
            })
        else:
            return jsonify({'error': 'Monitor not initialized'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/model/feedback', methods=['POST'])
def submit_model_feedback():
    """Submit feedback to improve the ML model"""
    try:
        data = request.json
        event_data = data.get('event_data', {})
        correct_label = data.get('correct_label', '')
        
        if not event_data or not correct_label:
            return jsonify({'error': 'Missing event_data or correct_label'}), 400
        
        # Import and use the threat model
        from ml_models.threat_detection_model import threat_model
        threat_model.add_feedback(event_data, correct_label)
        
        logger.info(f"📚 Model feedback received: {correct_label}")
        return jsonify({
            'status': 'success',
            'message': 'Feedback submitted for model improvement'
        })
        
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🌐 Real-Time Monitor API Server")
    print("=" * 40)
    print("📡 Interface monitoring API")
    print("🤖 ML model integration")
    print("📊 Real-time statistics")
    print("🔄 Continuous learning support")
    print()
    print("API Endpoints:")
    print("  GET  /api/health - Health check")
    print("  GET  /api/interfaces - Available interfaces")
    print("  GET  /api/stats - Monitoring statistics")
    print("  GET  /api/threats/recent - Recent threats")
    print("  POST /api/start - Start monitoring")
    print("  POST /api/stop - Stop monitoring")
    print("  POST /api/block/<ip> - Block IP address")
    print("  POST /api/model/feedback - Submit model feedback")
    print()
    print("🚀 Starting API server on http://0.0.0.0:8005")
    print("   Connect your dashboard to this API")
    print("   Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=8005, debug=False)