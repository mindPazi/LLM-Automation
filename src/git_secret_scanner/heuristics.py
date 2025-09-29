import re
import math
from collections import Counter

class HeuristicFilter:
    
    def __init__(self):
        self.entropy_threshold = 4.5
        self.secret_patterns = [
            (r'["\']?([Aa][Pp][Ii][_-]?[Kk][Ee][Yy])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
            (r'["\']?([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
            (r'["\']?([Tt][Oo][Kk][Ee][Nn])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
            (r'["\']?([Ss][Ee][Cc][Rr][Ee][Tt])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret'),
            (r'["\']?([Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'access_key'),
            (r'["\']?([Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'private_key'),
            (r'["\']?([Aa][Uu][Tt][Hh])[_-]?([Tt][Oo][Kk][Ee][Nn])["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'auth_token'),
        ]
        
        self.known_patterns = {
            'aws_access_key': r'^AKIA[0-9A-Z]{16}$',
            'github_token': r'^(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}$',
            'jwt_token': r'^eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$',
            'bearer_token': r'^Bearer\s+[a-zA-Z0-9-._~+/]+=*$',
            'slack_token': r'^xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}$'
        }
    
    def apply_filters(self, potential_issues):
        filtered_issues = []
        
        for issue in potential_issues:
            
            if 'secret_value' in issue:
                value = issue['secret_value']
                validation_result = self._validate_secret_value(value, min_entropy=2.0)
                
                if validation_result['is_valid']:
                    filtered_issues.append(issue)
            else:
                filtered_issues.append(issue)
        
        return filtered_issues
    
    def apply_regex_filters(self, content):
        findings = []
        
        lines = content.split('\n') if isinstance(content, str) else content
        
        for line_num, line in enumerate(lines, 1):
            for pattern_regex, pattern_type in self.secret_patterns:
                matches = re.findall(pattern_regex, line, re.IGNORECASE)
                
                for match in matches:
                    
                    if len(match) == 3:  
                        key = f"{match[0]}_{match[1]}"
                        value = match[2]
                    else:
                        key = match[0] if match else pattern_type
                        value = match[1] if len(match) > 1 else ""
                    
                    
                    if self._is_valid_secret(value):
                        findings.append({
                            'line_number': line_num,
                            'line': line[:200],  
                            'pattern_type': pattern_type,
                            'secret_key': key,
                            'secret_value': value[:50] + "..." if len(value) > 50 else value,
                            'entropy': self.calculate_entropy(value)
                        })
                        break  
        
        return findings
    
    def calculate_entropy(self, string):
        if not string:
            return 0.0
        
        
        char_counts = Counter(string)
        length = len(string)
        
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_valid_secret(self, value):
        if not value or len(value) < 6:
            return False
        
        if value.startswith("${") or value.startswith("%(") or value.startswith("{{"):
            return False
        
        if ',' in value and value.count(',') >= 2:
            words = [w.strip() for w in value.split(',')]
            keyword_count = sum(1 for w in words if any(kw in w.lower() for kw in 
                ['password', 'secret', 'token', 'key', 'api', 'auth', 'credential', 'private']))
            if keyword_count >= 3:
                return False
        
        if value.count(' ') > 5:
            return False
        
        test_values = ['password', 'secret', 'token', 'key', 'test', 'demo', 
                      'example', 'sample', 'dummy', 'fake', 'placeholder',
                      'super_secret_value', 'secret_value', 'secret_key']
        if value.lower() in test_values:
            return False
        
        value_lower = value.lower()
        if ('_secret_' in value_lower or 
            '_test_' in value_lower or 
            '_demo_' in value_lower or
            '_example_' in value_lower or
            '_sample_' in value_lower):
            return False
        
        return True
    
    def _is_placeholder(self, value):
        placeholders = [
            'xxx', '***', '...', '---',
            'your_', 'my_', 'the_',
            'todo', 'fixme', 'changeme',
            'replace', 'update'
        ]
        
        value_lower = value.lower()
        for placeholder in placeholders:
            if placeholder in value_lower:
                return True
        
        return False
    
    def validate_llm_finding(self, key, value):
        if not value or not key:
            return False
        
        if ',' in value and value.count(',') >= 2:
            return False
        
        if value.count(' ') > 5:
            return False
        
        validation_result = self._validate_secret_value(value, min_entropy=2.0)
        if not validation_result['is_valid']:
            return False
        
        key_lower = key.lower()
        secret_keywords = ['password', 'secret', 'token', 'key', 'api', 'auth', 'credential', 'access']
        has_secret_keyword = any(keyword in key_lower for keyword in secret_keywords)
        
        if not has_secret_keyword and validation_result['entropy'] < 3.5:
            return False
        
        return True
    
    def adjust_confidence_with_heuristics(self, initial_confidence, key, value):
        confidence = initial_confidence
        threshold = 0.5
        
        
        
        if '-' in value and not value.startswith('sk-') and not value.startswith('ghp_'):
            
            if any(char.isdigit() for char in value) or value.count('-') >= 2:
                confidence *= 0.2
        
        
        if '_' in value and value.isupper():
            
            confidence *= 0.15
        elif '_' in value and not any(char.isupper() for char in value):
            
            if value.endswith('_secret') or value.endswith('_key') or value.endswith('_token'):
                confidence *= 0.2
        
        
        code_literals = ['secret', 'key', 'token', 'password', 'fallback', 'default', 'type', 'name']
        if any(value.lower() == literal or value.lower().endswith(f'_{literal}') for literal in code_literals):
            confidence *= 0.1
        
        
        entropy = self.calculate_entropy(value)
        if entropy < 2.5:  
            confidence *= 0.3
        elif entropy < 3.0:
            confidence *= 0.5
        
        
        pem_markers = [
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----END RSA PRIVATE KEY-----',
            '-----BEGIN PRIVATE KEY-----',
            '-----END PRIVATE KEY-----',
            '-----BEGIN PUBLIC KEY-----',
            '-----END PUBLIC KEY-----',
            '-----BEGIN CERTIFICATE-----',
            '-----END CERTIFICATE-----',
            '-----BEGIN RSA PUBLIC KEY-----',
            '-----END RSA PUBLIC KEY-----'
        ]
        if value in pem_markers or value.startswith('-----BEGIN') or value.startswith('-----END'):
            confidence *= 0.1  
        
        
        test_values = [
            'super_secret_value', 'secret_value', 'secret_key',
            'password', 'secret', 'token', 'key', 'test', 'demo',
            'example', 'sample', 'dummy', 'fake', 'placeholder',
            'your_password', 'my_password', 'the_password',
            'your_secret', 'my_secret', 'the_secret',
            'your_token', 'my_token', 'the_token',
            'your_key', 'my_key', 'the_key'
        ]
        value_lower = value.lower()
        if value_lower in test_values:
            confidence *= 0.2  
        
        
        if ('_secret_' in value_lower or 
            '_test_' in value_lower or 
            '_demo_' in value_lower or
            '_example_' in value_lower or
            '_sample_' in value_lower or
            'super_' in value_lower):
            confidence *= 0.25
        
        if ',' in value and value.count(',') >= 1:
            confidence *= 0.3
        
        if value.count(' ') > 3:
            confidence *= 0.5
        
        entropy = self.calculate_entropy(value)
        if entropy < 2.0:
            confidence *= 0.6
        elif entropy > 4.0:
            confidence *= 1.2
        
        weak_patterns = ['test', 'demo', 'example', 'sample', 'dummy', 'fake', 'placeholder']
        if any(pattern in value_lower for pattern in weak_patterns):
            confidence *= 0.3  
        
        
        is_test_value = any(test_val in value_lower for test_val in test_values)
        if not is_test_value:
            for pattern_name, pattern in self.known_patterns.items():
                if re.match(pattern, value):
                    confidence *= 1.3
                    break
        
        key_lower = key.lower() if key else ""
        strong_keywords = ['password', 'secret', 'token', 'key', 'api', 'auth']
        if any(kw in key_lower for kw in strong_keywords):
            
            if not is_test_value and value not in pem_markers:
                confidence *= 1.1
        
        if len(value) < 8:
            confidence *= 0.7
        elif len(value) > 100:
            confidence *= 0.8
        
        confidence = min(1.0, max(0.0, confidence))
        
        should_filter = confidence < threshold
        
        return confidence, should_filter
    
    def _validate_secret_value(self, value, min_entropy=2.0): 
        result = {
            'is_valid': False,
            'entropy': 0.0,
            'reason': None
        }
        
        if not self._is_valid_secret(value):
            result['reason'] = 'Invalid secret format or test value'
            return result
        
        if self._is_placeholder(value):
            result['reason'] = 'Placeholder value'
            return result
        
        entropy = self.calculate_entropy(value)
        result['entropy'] = entropy
        
        if entropy < min_entropy:
            result['reason'] = f'Entropy too low: {entropy:.2f} < {min_entropy}'
            return result
        
        result['is_valid'] = True
        return result
    
    def calculate_confidence(self, secret_key, secret_value, secret_type=None):
        if ',' in secret_value and secret_value.count(',') >= 2:
            return 0.2
        
        if secret_value.count(' ') > 5:
            return 0.3
        
        
        base_confidence = 0.3
        
        entropy_score = self._calculate_entropy_score(secret_value)
        
        length_score = self._calculate_length_score(secret_value)
        
        type_score = self._calculate_type_score(secret_key, secret_value, secret_type)
        
        complexity_score = self._calculate_complexity_score(secret_value)
        
        total_score = base_confidence + entropy_score + length_score + type_score + complexity_score
        
        return min(1.0, max(0.4, total_score))
    
    def _calculate_entropy_score(self, value):
        entropy = self.calculate_entropy(value)
        
        if entropy > 4.5:
            return 0.35
        elif entropy > 3.0:
            return 0.25
        elif entropy > 2.0:
            return 0.15
        else:
            return 0.05
    
    def _calculate_length_score(self, value):
        length = len(value)
        
        if 20 <= length <= 64:
            return 0.25
        elif (12 <= length < 20) or (65 <= length <= 100):
            return 0.20
        elif 8 <= length < 12:
            return 0.15
        elif 6 <= length < 8:
            return 0.10
        else:
            return 0.05
    
    def _calculate_type_score(self, key, value, secret_type=None):
        
        for pattern_name, pattern in self.known_patterns.items():
            if re.match(pattern, value):
                return 0.25
        
        key_lower = key.lower() if key else ""
        
        if 'api' in key_lower and 'key' in key_lower:
            return 0.23
        elif 'token' in key_lower or 'bearer' in value.lower():
            return 0.22
        elif 'password' in key_lower or 'pass' in key_lower:
            return 0.20
        elif 'secret' in key_lower or 'key' in key_lower:
            return 0.18
        elif secret_type:
            return 0.15
        else:
            return 0.10
    
    def _calculate_complexity_score(self, value):
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(not c.isalnum() for c in value)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_count == 4:
            return 0.15
        elif complexity_count == 3:
            return 0.12
        elif complexity_count == 2:
            return 0.08
        else:
            return 0.05
