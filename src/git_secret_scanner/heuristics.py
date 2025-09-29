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
    
    def apply_filters(self, potential_issues):
        filtered_issues = []
        
        for issue in potential_issues:
            
            if 'secret_value' in issue:
                value = issue['secret_value']
                entropy = self.calculate_entropy(value)
                
                
                if entropy < 2.0:  
                    continue
                
                
                if self._is_placeholder(value):
                    continue
                
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
        
        
        test_values = ['password', 'secret', 'token', 'key', 'test', 'demo', 
                      'example', 'sample', 'dummy', 'fake', 'placeholder']
        if value.lower() in test_values:
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
