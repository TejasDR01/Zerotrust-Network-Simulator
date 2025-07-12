# main.py
import asyncio
import json
import time
import uuid
import threading
import random
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque

from flask import Flask, request, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DeviceType(Enum):
    ROUTER = "router"
    SERVER = "server"
    WORKSTATION = "workstation"
    MOBILE = "mobile"
    IOT = "iot"

class AccessDecision(Enum):
    ALLOW = "allowed"
    DENY = "denied"
    CHALLENGE = "challenged"

class SecurityModel(Enum):
    ZEROTRUST = "zerotrust"
    TRADITIONAL = "traditional"

@dataclass
class Device:
    device_id: str
    device_type: DeviceType
    ip_address: str
    trust_score: float
    is_compromised: bool = False
    location: str = "office"
    x: float = 0
    y: float = 0

@dataclass
class User:
    user_id: str
    name: str
    role: str
    risk_score: float
    department: str

@dataclass
class AccessRequest:
    user_id: str
    device_id: str
    resource: str
    action: str
    timestamp: float

class ZeroTrustNetworkSimulator:
    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.users: Dict[str, User] = {}
        self.network_graph: Dict[str, Set[str]] = defaultdict(set)
        self.activity_stats = {
            'allowed': 0,
            'denied': 0,
            'challenged': 0,
            'total_requests': 0
        }
        self.attack_sessions: Dict[str, Dict] = {}
        self._initialize_network()
        
    def _initialize_network(self):
        """Initialize the network with devices and connections"""
        # Create devices with fixed positions for consistent visualization
        devices_config = [
            ("firewall-01", DeviceType.ROUTER, "192.168.1.1", 0.95, 400, 100),
            ("dc-server-01", DeviceType.SERVER, "192.168.1.10", 0.9, 300, 200),
            ("db-server-01", DeviceType.SERVER, "192.168.1.11", 0.85, 500, 200),
            ("ws-finance-01", DeviceType.WORKSTATION, "192.168.2.10", 0.8, 200, 300),
            ("ws-finance-02", DeviceType.WORKSTATION, "192.168.2.11", 0.9, 350, 350),
            ("ws-hr-01", DeviceType.WORKSTATION, "192.168.2.20", 0.7, 450, 350),
            ("ws-it-01", DeviceType.WORKSTATION, "192.168.2.30", 0.95, 600, 300),
            ("mobile-ceo", DeviceType.MOBILE, "10.0.1.5", 0.8, 100, 400),
            ("printer-01", DeviceType.IOT, "192.168.3.10", 0.4, 700, 400),
        ]
        
        for device_id, device_type, ip, trust, x, y in devices_config:
            device = Device(
                device_id=device_id,
                device_type=device_type,
                ip_address=ip,
                trust_score=trust,
                x=x,
                y=y
            )
            self.devices[device_id] = device
            
        # Create network connections
        connections = [
            ("firewall-01", "dc-server-01"),
            ("firewall-01", "db-server-01"),
            ("firewall-01", "ws-finance-01"),
            ("firewall-01", "ws-finance-02"),
            ("firewall-01", "ws-hr-01"),
            ("firewall-01", "ws-it-01"),
            ("firewall-01", "mobile-ceo"),
            ("firewall-01", "printer-01"),
            ("dc-server-01", "db-server-01"),
            ("ws-finance-01", "ws-finance-02"),
        ]
        
        for device1, device2 in connections:
            self.network_graph[device1].add(device2)
            self.network_graph[device2].add(device1)
            
        # Create users
        users_config = [
            ("alice.finance", "Alice Johnson", "CFO", 0.3, "finance"),
            ("bob.it", "Bob Wilson", "IT Admin", 0.2, "it"),
            ("carol.hr", "Carol Brown", "HR Manager", 0.4, "hr"),
            ("dave.sales", "Dave Miller", "Sales Rep", 0.5, "sales"),
            ("eve.contractor", "Eve Davis", "Contractor", 0.8, "external"),
            ("frank.intern", "Frank Smith", "Intern", 0.6, "intern"),
        ]
        
        for user_id, name, role, risk, dept in users_config:
            self.users[user_id] = User(user_id, name, role, risk, dept)
            
    def get_network_topology(self) -> Dict:
        """Get network topology for frontend"""
        nodes = []
        links = []
        
        for device in self.devices.values():
            nodes.append({
                'id': device.device_id,
                'type': device.device_type.value,
                'trust_score': device.trust_score,
                'is_compromised': device.is_compromised,
                'x': device.x,
                'y': device.y
            })
            
        for source, targets in self.network_graph.items():
            for target in targets:
                if source < target:  # Avoid duplicate links
                    links.append({
                        'source': source,
                        'target': target
                    })
                    
        return {'nodes': nodes, 'links': links}
    
    def evaluate_zerotrust_access(self, request: AccessRequest) -> Dict:
        """Evaluate access request using zero-trust principles"""
        user = self.users.get(request.user_id)
        device = self.devices.get(request.device_id)
        
        if not user or not device:
            return {
                'decision': AccessDecision.DENY,
                'reason': 'Unknown user or device',
                'trust_score': 0.0
            }
        
        # Zero-trust evaluation factors
        user_risk = user.risk_score
        device_trust = device.trust_score
        resource_sensitivity = self._get_resource_sensitivity(request.resource)
        time_risk = self._get_time_risk(request.timestamp)
        
        # Calculate overall risk score (0 = low risk, 1 = high risk)
        risk_factors = {
            'user_risk': user_risk * 0.3,
            'device_risk': (1 - device_trust) * 0.3,
            'resource_sensitivity': resource_sensitivity * 0.25,
            'time_risk': (1 - time_risk) * 0.15
        }
        
        overall_risk = sum(risk_factors.values())
        
        # Zero-trust decision logic
        if overall_risk < 0.5:
            decision = AccessDecision.ALLOW
            reason = "Low risk profile - access granted"
        elif overall_risk < 0.8:
            decision = AccessDecision.CHALLENGE
            reason = "Medium risk - additional verification required"
        else:
            decision = AccessDecision.DENY
            reason = "High risk profile - access denied"
        
        # Additional zero-trust checks
        if device.is_compromised:
            decision = AccessDecision.DENY
            reason = "Device compromised - access blocked"
        elif resource_sensitivity > 0.8 and device_trust < 0.8:
            decision = AccessDecision.DENY
            reason = "Insufficient device trust for sensitive resource"
        elif user.department == "external" and resource_sensitivity > 0.5:
            decision = AccessDecision.CHALLENGE
            reason = "External user accessing internal resource"
        
        return {
            'decision': decision,
            'reason': reason,
            'trust_score': 1 - overall_risk,
            'risk_factors': risk_factors
        }
    
    def _get_resource_sensitivity(self, resource: str) -> float:
        """Get resource sensitivity score (0-1)"""
        sensitivity_map = {
            'database': 0.9,
            'financial_data': 0.95,
            'customer_data': 0.85,
            'admin_panel': 0.9,
            'hr_records': 0.8,
            'source_code': 0.7,
            'file_share': 0.5,
            'email': 0.3,
            'printer': 0.2,
            'web_app': 0.4,
            'reports': 0.6
        }
        return sensitivity_map.get(resource, 0.5)
    
    def _get_time_risk(self, timestamp: float) -> float:
        """Get time-based risk factor (0-1, higher = safer)"""
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        
        # Business hours are safer
        if 9 <= hour <= 17:  # Business hours
            return 0.9
        elif 7 <= hour < 9 or 17 < hour <= 20:  # Extended hours
            return 0.6
        else:  # Night/early morning
            return 0.2
    
    def simulate_normal_activity(self, socketio_instance):
        """Simulate 10 random access requests for zero-trust model"""
        def generate_activity():
            resources = [
                'email', 'file_share', 'database', 'web_app', 'printer', 
                'admin_panel', 'reports', 'customer_data', 'financial_data', 'hr_records'
            ]
            
            for i in range(10):  # Generate exactly 10 requests
                # Random user and device (prefer workstations and servers for realistic simulation)
                eligible_devices = [d for d in self.devices.keys() 
                                  if self.devices[d].device_type != DeviceType.ROUTER]
                
                user_id = random.choice(list(self.users.keys()))
                device_id = random.choice(eligible_devices)
                resource = random.choice(resources)
                
                request = AccessRequest(
                    user_id=user_id,
                    device_id=device_id,
                    resource=resource,
                    action='access',
                    timestamp=time.time()
                )
                
                # Evaluate with zero-trust model only
                decision_result = self.evaluate_zerotrust_access(request)
                decision_type = decision_result['decision'].value
                
                # Update statistics
                self.activity_stats[decision_type] += 1
                self.activity_stats['total_requests'] += 1
                
                # Send real-time update to dashboard
                activity_data = {
                    'type': 'activity_update',
                    'user': user_id,
                    'resource': resource,
                    'decision': decision_type,
                    'reason': decision_result['reason'],
                    'timestamp': time.time() * 1000,  # Convert to milliseconds for JS
                    'stats': self.activity_stats.copy()
                }
                
                socketio_instance.emit('activity_update', activity_data)
                
                # Random delay between requests (0.5 to 2 seconds)
                time.sleep(random.uniform(0.5, 2.0))
        
        # Run in background thread
        thread = threading.Thread(target=generate_activity, daemon=True)
        thread.start()
        return {"status": "Activity simulation started", "requests": 10}
    
    def simulate_lateral_movement_attack(self, model: SecurityModel, socketio_instance):
        """Simulate lateral movement attack for both models"""
        # Select random entry point (prefer workstations as typical entry points)
        devices = [d for d in self.devices.keys() 
                       if self.devices[d].device_type != DeviceType.ROUTER]
        entry_point = random.choice(devices)
        
        attack_id = str(uuid.uuid4())
        
        def run_attack():
            if model == SecurityModel.TRADITIONAL:
                self._simulate_traditional_attack(attack_id, entry_point, socketio_instance)
            else:
                self._simulate_zerotrust_attack(attack_id, entry_point, socketio_instance)
        
        # Run attack in background thread
        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()
        
        return {
            "status": "Attack simulation started",
            "model": model.value,
            "entry_point": entry_point,
            "attack_id": attack_id
        }
    
    def _simulate_traditional_attack(self, attack_id: str, entry_point: str, socketio):
        """Simulate traditional network attack - spreads everywhere"""
        compromised = {entry_point}
        all_devices = list(self.devices.keys())
        
        # Mark entry point as compromised
        self.devices[entry_point].is_compromised = True
        
        # Send initial compromise notification
        socketio.emit('attack_update', {
            'type': 'attack_progress',
            'step': {
                'source': 'external',
                'target': entry_point,
                'result': 'success',
                'model': 'traditional',
                'reason': 'Initial compromise via phishing/malware'
            },
            'compromised_nodes': list(compromised),
            'attack_id': attack_id
        })
        
        time.sleep(1.5)  # Initial delay
        
        # In traditional networks, lateral movement is easy
        for target in all_devices:
            if target != entry_point:
                time.sleep(random.uniform(1.0, 2.0))  # Realistic spread timing
                
                # Traditional networks: most lateral movement succeeds:
                compromised.add(target)
                self.devices[target].is_compromised = True
                step_data = {
                    'type': 'attack_progress',
                    'step': {
                        'source': random.choice(list(compromised - {target})),
                        'target': target,
                        'result': 'success',
                        'model': 'traditional',
                        'reason': 'Lateral movement via shared credentials/network access'
                    },
                    'compromised_nodes': list(compromised),
                    'attack_id': attack_id
                }
                socketio.emit('attack_update', step_data)
        
        # Final results
        total_devices = len(all_devices)
        compromised_count = len(compromised)
        containment_effectiveness = f"{((total_devices - compromised_count) / total_devices) * 100:.1f}%"
        
        results = {
            'type': 'attack_complete',
            'results': {
                'model': 'traditional',
                'compromised_count': compromised_count,
                'total_nodes': total_devices,
                'containment_effectiveness': containment_effectiveness,
                'attack_id': attack_id,
                'entry_point': entry_point,
                'duration': time.time()
            }
        }
        socketio.emit('attack_update', results)
    
    def _simulate_zerotrust_attack(self, attack_id: str, entry_point: str, socketio):
        """Simulate zero-trust attack - contained at entry point"""
        compromised = {entry_point}
        self.devices[entry_point].is_compromised = True
        
        # Send initial compromise
        socketio.emit('attack_update', {
            'type': 'attack_progress',
            'step': {
                'source': 'external',
                'target': entry_point,
                'result': 'success',
                'model': 'zerotrust',
                'reason': 'Initial compromise via social engineering'
            },
            'compromised_nodes': list(compromised),
            'attack_id': attack_id
        })
        
        time.sleep(1.5)
        
        # Attempt lateral movement - zero-trust blocks most attempts
        neighbors = list(self.network_graph[entry_point])
        attempted_targets = neighbors[:4]  # Try first 4 connected devices
        
        for i, target in enumerate(attempted_targets):
            time.sleep(random.uniform(1.0, 1.8))
            
            # Zero-trust: very low success rate for lateral movement
            success_rate = 0.1  # Only 10% chance of success
            
            if random.random() < success_rate:
                # Rare successful lateral movement
                compromised.add(target)
                self.devices[target].is_compromised = True
                result = 'success'
                reason = 'Lateral movement succeeded despite zero-trust (rare vulnerability)'
            else:
                # Most attempts blocked
                result = 'blocked'
                reason = 'Zero-trust policy blocked lateral movement - continuous verification failed'
            
            step_data = {
                'type': 'attack_progress',
                'step': {
                    'source': entry_point,
                    'target': target,
                    'result': result,
                    'model': 'zerotrust',
                    'reason': reason
                },
                'compromised_nodes': list(compromised),
                'attack_id': attack_id
            }
            socketio.emit('attack_update', step_data)
        
        # Final results - attack contained
        total_devices = len(self.devices)
        compromised_count = len(compromised)
        containment_effectiveness = f"{((total_devices - compromised_count) / total_devices) * 100:.1f}%"
        
        results = {
            'type': 'attack_complete',
            'results': {
                'model': 'zerotrust',
                'compromised_count': compromised_count,
                'total_nodes': total_devices,
                'containment_effectiveness': containment_effectiveness,
                'attack_id': attack_id,
                'entry_point': entry_point,
                'duration': time.time()
            }
        }
        socketio.emit('attack_update', results)
    
    def reset_network(self):
        """Reset network to clean state"""
        for device in self.devices.values():
            device.is_compromised = False
        
        self.activity_stats = {
            'allowed': 0,
            'denied': 0,
            'challenged': 0,
            'total_requests': 0
        }
        
        self.attack_sessions.clear()

# Flask Application with SocketIO
app = Flask(__name__, template_folder="web")
app.config['SECRET_KEY'] = 'zerotrust-dashboard-demo'
socketio = SocketIO(app, async_mode='threading')

# Global simulator instance
simulator = ZeroTrustNetworkSimulator()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/network/topology')
def get_network_topology():
    """Get network topology for visualization"""
    try:
        topology = simulator.get_network_topology()
        return jsonify(topology)
    except Exception as e:
        logger.error(f"Error getting topology: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/status')
def get_network_status():
    """Get current network status"""
    try:
        compromised_count = sum(1 for device in simulator.devices.values() if device.is_compromised)
        
        status = {
            'total_devices': len(simulator.devices),
            'compromised_devices': compromised_count,
            'network_health': 'HEALTHY' if compromised_count == 0 else 'COMPROMISED',
            'stats': simulator.activity_stats
        }
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate/attack', methods=['POST'])
def simulate_attack():
    """Start attack simulation"""
    try:
        data = request.json
        model = SecurityModel(data.get('model', 'zerotrust'))
        
        result = simulator.simulate_lateral_movement_attack(model, socketio)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting attack: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate/activity', methods=['POST'])
def simulate_activity():
    """Start normal activity simulation (Zero-Trust only)"""
    try:
        result = simulator.simulate_normal_activity(socketio)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting activity: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def reset_network():
    """Reset network to clean state"""
    try:
        simulator.reset_network()
        socketio.emit('network_reset', {'status': 'Network reset complete'})
        return jsonify({'status': 'Network reset successfully'})
    except Exception as e:
        logger.error(f"Error resetting network: {e}")
        return jsonify({'error': str(e)}), 500

# SocketIO Event Handlers
@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'Connected to Zero-Trust Simulator'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

@socketio.on('request_network_data')
def handle_network_request():
    """Handle real-time network data requests"""
    topology = simulator.get_network_topology()
    emit('network_data', topology)

@socketio.on('start_attack')
def handle_start_attack(data):
    """Handle attack simulation requests via WebSocket"""
    model = SecurityModel(data.get('model', 'zerotrust'))
    result = simulator.simulate_lateral_movement_attack(model, socketio)
    emit('attack_started', result)

@socketio.on('start_activity')
def handle_start_activity(data):
    """Handle activity simulation requests via WebSocket"""
    result = simulator.simulate_normal_activity(socketio)
    emit('activity_started', result)

@socketio.on('reset_network')
def handle_reset():
    """Handle network reset requests via WebSocket"""
    simulator.reset_network()
    emit('network_reset', {'status': 'Network reset complete'})

if __name__ == '__main__':
    logger.info("Starting Zero-Trust Network Simulator Backend")
    logger.info("Real-time WebSocket endpoint: ws://localhost:8080/socket.io/")
    logger.info("REST API endpoint: http://localhost:8080/api/")
    logger.info("Dashboard ready for connections")
    
    # Run with threading for better performance
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=8080,
        debug=True,
        use_reloader=False  # Disable reloader to prevent threading issues
    )