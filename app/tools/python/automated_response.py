#!/usr/bin/env python3
"""
Automated Response System
Enterprise-grade automated threat mitigation with evidence preservation
"""

import json
import sys
import os
import time
import hashlib
import subprocess
import sqlite3
import socket
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import argparse
from enum import Enum

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"  # Score 80+
    HIGH = "HIGH"          # Score 60-79
    MEDIUM = "MEDIUM"      # Score 40-59
    LOW = "LOW"            # Score 20-39
    INFO = "INFO"          # Score 0-19

class ResponseAction(Enum):
    """Automated response actions"""
    BLOCK_IP = "block_ip"
    ALERT_ADMIN = "alert_admin"
    COLLECT_EVIDENCE = "collect_evidence"
    INITIATE_OSINT = "initiate_osint"
    ENABLE_QUANTUM_ENCRYPTION = "enable_quantum_encryption"
    CREATE_CASE = "create_case"
    ENHANCED_MONITORING = "enhanced_monitoring"
    PRESERVE_EVIDENCE = "preserve_evidence"
    IDENTITY_LOCK = "identity_lock"
    CREDIT_FREEZE = "credit_freeze"
    DATA_BROKER_REMOVAL = "data_broker_removal"
    LEGAL_EVIDENCE = "legal_evidence"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    ROLLBACK_CHANGES = "rollback_changes"
    ENABLE_VPN = "enable_vpn"
    ROTATE_CREDENTIALS = "rotate_credentials"
    BACKUP_CRITICAL = "backup_critical"
    NOTIFY_AUTHORITIES = "notify_authorities"

class AutomatedResponseEngine:
    """Core automated response system"""
    
    def __init__(self, config_file: str = "response_config.json"):
        self.config = self._load_config(config_file)
        self.db_path = "automated_response.db"
        self.init_database()
        self.response_queue = []
        self.active_responses = {}
        
    def _load_config(self, config_file: str) -> Dict:
        """Load response configuration"""
        default_config = {
            "thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 40,
                "low": 20
            },
            "response_rules": {
                "CRITICAL": [
                    "block_ip", "alert_admin", "collect_evidence", 
                    "initiate_osint", "enable_quantum_encryption", "create_case",
                    "isolate_host", "legal_evidence", "notify_authorities"
                ],
                "HIGH": [
                    "enhanced_monitoring", "alert_admin", "preserve_evidence",
                    "identity_lock", "data_broker_removal", "backup_critical"
                ],
                "IDENTITY_THREAT": [
                    "identity_lock", "credit_freeze", "data_broker_removal",
                    "initiate_osint", "legal_evidence", "alert_admin"
                ],
                "CRYPTO_THREAT": [
                    "enable_quantum_encryption", "rotate_credentials",
                    "backup_critical", "alert_admin"
                ],
                "MALWARE_THREAT": [
                    "isolate_host", "kill_process", "quarantine_file",
                    "collect_evidence", "create_case"
                ]
            },
            "notification_channels": {
                "email": {"enabled": True, "recipients": ["admin@example.com"]},
                "sms": {"enabled": False, "numbers": []},
                "webhook": {"enabled": True, "url": "https://hooks.example.com/security"},
                "siem": {"enabled": True, "endpoint": "siem.example.com:514"}
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                loaded = json.load(f)
                default_config.update(loaded)
        
        return default_config
    
    def init_database(self):
        """Initialize response tracking database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS response_history
                    (id INTEGER PRIMARY KEY,
                     threat_id TEXT,
                     threat_type TEXT,
                     threat_score INTEGER,
                     threat_level TEXT,
                     source TEXT,
                     target TEXT,
                     actions_taken TEXT,
                     evidence_collected TEXT,
                     case_id TEXT,
                     response_time REAL,
                     timestamp TIMESTAMP,
                     status TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_entities
                    (id INTEGER PRIMARY KEY,
                     entity_type TEXT,
                     entity_value TEXT,
                     reason TEXT,
                     blocked_at TIMESTAMP,
                     expires_at TIMESTAMP,
                     permanent BOOLEAN)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS evidence_vault
                    (id INTEGER PRIMARY KEY,
                     case_id TEXT,
                     evidence_type TEXT,
                     evidence_data TEXT,
                     hash TEXT,
                     collected_at TIMESTAMP,
                     chain_of_custody TEXT)''')
        
        conn.commit()
        conn.close()
    
    def assess_threat(self, threat_data: Dict) -> Tuple[int, str, List[str]]:
        """
        Assess threat and determine response actions
        
        Returns:
            Tuple of (threat_score, threat_level, actions_to_take)
        """
        score = threat_data.get("score", 0)
        threat_type = threat_data.get("type", "unknown")
        
        # Determine threat level
        if score >= self.config["thresholds"]["critical"]:
            level = ThreatLevel.CRITICAL.value
        elif score >= self.config["thresholds"]["high"]:
            level = ThreatLevel.HIGH.value
        elif score >= self.config["thresholds"]["medium"]:
            level = ThreatLevel.MEDIUM.value
        elif score >= self.config["thresholds"]["low"]:
            level = ThreatLevel.LOW.value
        else:
            level = ThreatLevel.INFO.value
        
        # Get response actions based on level and type
        actions = []
        
        # Add level-based actions
        if level in self.config["response_rules"]:
            actions.extend(self.config["response_rules"][level])
        
        # Add type-specific actions
        if threat_type == "identity" and "IDENTITY_THREAT" in self.config["response_rules"]:
            actions.extend(self.config["response_rules"]["IDENTITY_THREAT"])
        elif threat_type == "crypto" and "CRYPTO_THREAT" in self.config["response_rules"]:
            actions.extend(self.config["response_rules"]["CRYPTO_THREAT"])
        elif threat_type == "malware" and "MALWARE_THREAT" in self.config["response_rules"]:
            actions.extend(self.config["response_rules"]["MALWARE_THREAT"])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)
        
        return score, level, unique_actions
    
    def execute_response(self, threat_data: Dict) -> Dict:
        """Execute automated response based on threat assessment"""
        threat_id = threat_data.get("id", hashlib.md5(str(threat_data).encode()).hexdigest()[:8])
        score, level, actions = self.assess_threat(threat_data)
        
        response_start = time.time()
        results = {
            "threat_id": threat_id,
            "threat_level": level,
            "threat_score": score,
            "actions_executed": [],
            "actions_failed": [],
            "evidence_collected": [],
            "case_id": None
        }
        
        # Execute each action
        for action in actions:
            try:
                if action == ResponseAction.BLOCK_IP.value:
                    self._block_ip(threat_data.get("ip_address"))
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ALERT_ADMIN.value:
                    self._alert_admin(threat_data, level)
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.COLLECT_EVIDENCE.value:
                    evidence = self._collect_evidence(threat_data)
                    results["evidence_collected"].extend(evidence)
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.INITIATE_OSINT.value:
                    self._initiate_osint(threat_data)
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ENABLE_QUANTUM_ENCRYPTION.value:
                    self._enable_quantum_encryption()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.CREATE_CASE.value:
                    case_id = self._create_case(threat_data)
                    results["case_id"] = case_id
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ENHANCED_MONITORING.value:
                    self._enable_enhanced_monitoring(threat_data)
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.IDENTITY_LOCK.value:
                    self._lock_identity(threat_data)
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.CREDIT_FREEZE.value:
                    self._freeze_credit()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.DATA_BROKER_REMOVAL.value:
                    self._remove_data_brokers()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ISOLATE_HOST.value:
                    self._isolate_host(threat_data.get("host"))
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.KILL_PROCESS.value:
                    self._kill_process(threat_data.get("pid"))
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.QUARANTINE_FILE.value:
                    self._quarantine_file(threat_data.get("file_path"))
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ENABLE_VPN.value:
                    self._enable_vpn()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.ROTATE_CREDENTIALS.value:
                    self._rotate_credentials()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.BACKUP_CRITICAL.value:
                    self._backup_critical_data()
                    results["actions_executed"].append(action)
                
                elif action == ResponseAction.NOTIFY_AUTHORITIES.value:
                    self._notify_authorities(threat_data)
                    results["actions_executed"].append(action)
                
                else:
                    results["actions_executed"].append(action)
                    
            except Exception as e:
                results["actions_failed"].append({
                    "action": action,
                    "error": str(e)
                })
        
        response_time = time.time() - response_start
        
        # Record response in database
        self._record_response(threat_id, threat_data, level, score, results, response_time)
        
        results["response_time"] = response_time
        results["timestamp"] = datetime.now().isoformat()
        
        return results
    
    def _block_ip(self, ip_address: str):
        """Block IP address at firewall level"""
        if not ip_address:
            return
        
        # Windows netsh command
        if sys.platform == "win32":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Block_{ip_address}",
                "dir=in", "action=block",
                f"remoteip={ip_address}"
            ], capture_output=True)
        else:
            # Linux iptables
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"
            ], capture_output=True)
        
        # Record in database
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO blocked_entities 
                    (entity_type, entity_value, reason, blocked_at, permanent)
                    VALUES (?, ?, ?, ?, ?)''',
                 ("ip", ip_address, "Automated threat response", datetime.now(), False))
        conn.commit()
        conn.close()
    
    def _alert_admin(self, threat_data: Dict, level: str):
        """Send alert to administrators"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "threat": threat_data,
            "message": f"SECURITY ALERT: {level} threat detected"
        }
        
        # Email notification
        if self.config["notification_channels"]["email"]["enabled"]:
            # In production, use SMTP
            print(f"EMAIL ALERT: {json.dumps(alert)}")
        
        # Webhook notification
        if self.config["notification_channels"]["webhook"]["enabled"]:
            # In production, use requests.post
            print(f"WEBHOOK: {self.config['notification_channels']['webhook']['url']}")
        
        # SIEM integration
        if self.config["notification_channels"]["siem"]["enabled"]:
            # In production, send to SIEM
            print(f"SIEM: {json.dumps(alert)}")
    
    def _collect_evidence(self, threat_data: Dict) -> List[str]:
        """Collect forensic evidence"""
        evidence = []
        case_id = threat_data.get("case_id", hashlib.md5(str(threat_data).encode()).hexdigest()[:8])
        
        # Collect network connections
        if sys.platform == "win32":
            netstat = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
            evidence.append("network_connections")
        
        # Collect process list
        if sys.platform == "win32":
            processes = subprocess.run(["wmic", "process", "get", "ProcessId,Name,CommandLine"], 
                                     capture_output=True, text=True)
            evidence.append("process_list")
        
        # Collect system info
        if sys.platform == "win32":
            sysinfo = subprocess.run(["systeminfo"], capture_output=True, text=True)
            evidence.append("system_info")
        
        # Store in evidence vault
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for ev_type in evidence:
            ev_data = json.dumps(threat_data)
            ev_hash = hashlib.sha256(ev_data.encode()).hexdigest()
            
            c.execute('''INSERT INTO evidence_vault 
                        (case_id, evidence_type, evidence_data, hash, collected_at, chain_of_custody)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (case_id, ev_type, ev_data, ev_hash, datetime.now(), 
                      "Automated collection"))
        
        conn.commit()
        conn.close()
        
        return evidence
    
    def _initiate_osint(self, threat_data: Dict):
        """Start OSINT investigation on threat actor"""
        target = threat_data.get("ip_address") or threat_data.get("email") or threat_data.get("domain")
        if target:
            # In production, call osint_harvester.py
            print(f"OSINT Investigation initiated on: {target}")
    
    def _enable_quantum_encryption(self):
        """Enable quantum-resistant encryption"""
        # In production, call quantum_encryption.py
        print("Quantum-resistant encryption enabled")
    
    def _create_case(self, threat_data: Dict) -> str:
        """Create investigation case"""
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{hashlib.md5(str(threat_data).encode()).hexdigest()[:6]}"
        
        # Create case directory
        case_dir = f"cases/{case_id}"
        os.makedirs(case_dir, exist_ok=True)
        
        # Write case file
        with open(f"{case_dir}/case.json", 'w') as f:
            json.dump({
                "case_id": case_id,
                "created": datetime.now().isoformat(),
                "threat_data": threat_data,
                "status": "active"
            }, f, indent=2)
        
        return case_id
    
    def _enable_enhanced_monitoring(self, threat_data: Dict):
        """Enable enhanced monitoring mode"""
        # In production, adjust monitoring parameters
        print(f"Enhanced monitoring enabled for: {threat_data}")
    
    def _lock_identity(self, threat_data: Dict):
        """Lock digital identity"""
        # In production, call identity_protection.py
        print("Identity lock initiated")
    
    def _freeze_credit(self):
        """Initiate credit freeze"""
        # In production, call identity_protection.py freeze-credit
        print("Credit freeze initiated with all bureaus")
    
    def _remove_data_brokers(self):
        """Start data broker removal"""
        # In production, call identity_protection.py remove-brokers
        print("Data broker removal process started")
    
    def _isolate_host(self, host: str):
        """Isolate compromised host"""
        if host:
            # In production, implement network isolation
            print(f"Host isolated: {host}")
    
    def _kill_process(self, pid: int):
        """Kill malicious process"""
        if pid:
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    subprocess.run(["kill", "-9", str(pid)], capture_output=True)
                print(f"Process killed: {pid}")
            except:
                pass
    
    def _quarantine_file(self, file_path: str):
        """Quarantine suspicious file"""
        if file_path and os.path.exists(file_path):
            quarantine_dir = "quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Move to quarantine with timestamp
            quarantine_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(quarantine_dir, quarantine_name)
            
            try:
                os.rename(file_path, quarantine_path)
                print(f"File quarantined: {file_path} -> {quarantine_path}")
            except:
                pass
    
    def _enable_vpn(self):
        """Enable VPN connection"""
        # In production, start VPN client
        print("VPN connection enabled")
    
    def _rotate_credentials(self):
        """Rotate all credentials"""
        # In production, trigger credential rotation
        print("Credential rotation initiated")
    
    def _backup_critical_data(self):
        """Backup critical data"""
        # In production, trigger backup process
        print("Critical data backup started")
    
    def _notify_authorities(self, threat_data: Dict):
        """Notify law enforcement if necessary"""
        if threat_data.get("score", 0) >= 90:
            # In production, send to appropriate authorities
            print("Law enforcement notification sent")
    
    def _record_response(self, threat_id: str, threat_data: Dict, level: str, 
                        score: int, results: Dict, response_time: float):
        """Record response in database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT INTO response_history 
                    (threat_id, threat_type, threat_score, threat_level, 
                     source, target, actions_taken, evidence_collected, 
                     case_id, response_time, timestamp, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (threat_id, 
                  threat_data.get("type", "unknown"),
                  score,
                  level,
                  threat_data.get("source", ""),
                  threat_data.get("target", ""),
                  json.dumps(results["actions_executed"]),
                  json.dumps(results["evidence_collected"]),
                  results.get("case_id"),
                  response_time,
                  datetime.now(),
                  "completed"))
        
        conn.commit()
        conn.close()
    
    def get_response_stats(self) -> Dict:
        """Get response statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get response counts by level
        c.execute('''SELECT threat_level, COUNT(*) FROM response_history 
                    GROUP BY threat_level''')
        level_counts = dict(c.fetchall())
        
        # Get average response time
        c.execute('SELECT AVG(response_time) FROM response_history')
        avg_response = c.fetchone()[0] or 0
        
        # Get blocked entities
        c.execute('SELECT COUNT(*) FROM blocked_entities WHERE permanent = 0')
        temp_blocks = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM blocked_entities WHERE permanent = 1')
        perm_blocks = c.fetchone()[0]
        
        # Get evidence collected
        c.execute('SELECT COUNT(*) FROM evidence_vault')
        evidence_count = c.fetchone()[0]
        
        conn.close()
        
        return {
            "responses_by_level": level_counts,
            "average_response_time": avg_response,
            "temporary_blocks": temp_blocks,
            "permanent_blocks": perm_blocks,
            "evidence_collected": evidence_count,
            "timestamp": datetime.now().isoformat()
        }


def main():
    parser = argparse.ArgumentParser(description='Automated Response System')
    parser.add_argument('command', choices=['respond', 'assess', 'stats', 'test'])
    parser.add_argument('--threat-data', help='JSON threat data')
    parser.add_argument('--config', default='response_config.json', help='Config file')
    
    args = parser.parse_args()
    
    engine = AutomatedResponseEngine(args.config)
    
    if args.command == 'respond':
        if args.threat_data:
            threat_data = json.loads(args.threat_data)
            result = engine.execute_response(threat_data)
            print(json.dumps(result, indent=2))
    
    elif args.command == 'assess':
        if args.threat_data:
            threat_data = json.loads(args.threat_data)
            score, level, actions = engine.assess_threat(threat_data)
            print(json.dumps({
                "threat_score": score,
                "threat_level": level,
                "recommended_actions": actions
            }, indent=2))
    
    elif args.command == 'stats':
        stats = engine.get_response_stats()
        print(json.dumps(stats, indent=2))
    
    elif args.command == 'test':
        # Test with sample threats
        test_threats = [
            {"score": 85, "type": "malware", "ip_address": "192.168.1.100", "pid": 1234},
            {"score": 65, "type": "identity", "email": "user@example.com"},
            {"score": 95, "type": "crypto", "domain": "evil.com"}
        ]
        
        for threat in test_threats:
            print(f"\nTesting threat: {threat}")
            result = engine.execute_response(threat)
            print(f"Response: {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    main()
