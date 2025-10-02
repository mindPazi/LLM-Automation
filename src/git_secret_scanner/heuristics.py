import re
import math
from typing import List, Dict, Any, Tuple, Optional
import git
from collections import Counter
from src.git_secret_scanner.config_loader import config
from src.git_secret_scanner.logger_config import get_logger

logger = get_logger(__name__)

class HeuristicFilter:
    
    def __init__(self) -> None:
        logger.info("Initializing HeuristicFilter")
        
        self.min_secret_length = config.get('validation', 'min_secret_length')
        self.filter_threshold = config.get('heuristics', 'confidence', 'filter_threshold')
        
        self.known_prefixes = config.get('validation', 'known_prefixes')
        
        patterns_config = config.get('patterns', 'secret_patterns')
        self.secret_patterns = []
        for pattern_dict in patterns_config:
            if isinstance(pattern_dict, dict) and 'pattern' in pattern_dict and 'type' in pattern_dict:
                self.secret_patterns.append((pattern_dict['pattern'], pattern_dict['type']))
        
        logger.info("HeuristicFilter initialized successfully")
    
    def apply_filters(self, potential_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered_issues = []
        
        for issue in potential_issues:
            if 'secret_value' in issue:
                value = issue['secret_value']
                validation_result = self._validate_secret_value(value)
                
                if validation_result['is_valid']:
                    filtered_issues.append(issue)
                else:
                    logger.error(f"Filtered out: {validation_result.get('reason', 'unknown reason')}")
            else:
                filtered_issues.append(issue)
        
        return filtered_issues
    
    def apply_regex_filters(self, content: Any) -> List[Dict[str, Any]]:
        findings = []
        found_secrets = set()  
        
        lines = content.split('\n') if isinstance(content, str) else content
        
        for line_num, line in enumerate(lines, 1):
            line_has_secret = False  
            
            for pattern_regex, pattern_type in self.secret_patterns:
                if line_has_secret:
                    break  
                    
                matches = re.findall(pattern_regex, line, re.IGNORECASE)
                
                for match in matches:
                    
                    if len(match) == 3:  
                        key = f"{match[0]}_{match[1]}"
                        value = match[2]
                    elif len(match) == 2:  
                        key = match[0]
                        value = match[1]
                    else:
                        key = match[0] if match else pattern_type
                        value = match[1] if len(match) > 1 else ""
                    
                    
                    secret_id = f"{line_num}:{key}:{value}"
                    
                    
                    if secret_id in found_secrets:
                        continue
                    
                    if self._is_valid_secret(value):
                        entropy = self.calculate_entropy(value)
                        findings.append({
                            'line_number': line_num,
                            'line': line[:200],  
                            'pattern_type': pattern_type,
                            'secret_key': key,
                            'secret_value': value[:50] + "..." if len(value) > 50 else value,
                            'entropy': entropy
                        })
                        found_secrets.add(secret_id)
                        line_has_secret = True  
                        break  
        
        logger.info(f"Regex filters found {len(findings)} potential secrets")
        return findings
    
    def calculate_entropy(self, string: str) -> float:
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
    
    def _detect_sequences(self, string: str) -> float:
        if not string or len(string) < 3:
            return 0.0
        
        string_lower = string.lower()
        penalty = 0.0
        
        
        alpha_sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'zyxwvutsrqponmlkjihgfedcba'
        ]
        
        for seq in alpha_sequences:
            for i in range(len(string_lower) - 2):
                substr = string_lower[i:i+3]
                if substr in seq:
                    
                    seq_length = 3
                    while i + seq_length < len(string_lower) and \
                          string_lower[i:i+seq_length+1] in seq:
                        seq_length += 1
                    penalty = max(penalty, seq_length / len(string))
        
        
        numeric_sequences = [
            '0123456789',
            '9876543210'
        ]
        
        for seq in numeric_sequences:
            for i in range(len(string) - 2):
                substr = string[i:i+3]
                if substr in seq:
                    seq_length = 3
                    while i + seq_length < len(string) and \
                          string[i:i+seq_length+1] in seq:
                        seq_length += 1
                    penalty = max(penalty, seq_length / len(string))
        
        
        keyboard_patterns = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            'poiuytrewq',
            'lkjhgfdsa',
            'mnbvcxz',
            '1234567890',
            '0987654321',
            'qwerty',
            'asdfgh',
            'zxcvbn',
            'qazwsx',
            'qweasd'
        ]
        
        for pattern in keyboard_patterns:
            if pattern in string_lower:
                pattern_ratio = len(pattern) / len(string)
                penalty = max(penalty, pattern_ratio)
        
        
        for pattern_len in range(2, min(len(string)//2 + 1, 8)):
            pattern = string[:pattern_len]
            repetitions = 1
            for i in range(pattern_len, len(string), pattern_len):
                if string[i:i+pattern_len] == pattern:
                    repetitions += 1
                else:
                    break
            if repetitions >= 2:
                coverage = (repetitions * pattern_len) / len(string)
                if coverage >= 0.8:  
                    penalty = max(penalty, coverage)
        
        return min(penalty, 0.9)  
    
    def _is_valid_secret(self, value: str) -> bool:
        if not value or len(value) < self.min_secret_length:
            return False
        
        if value.startswith("${") or value.startswith("%(") or value.startswith("{{"):
            return False
        
        if value.count(' ') > 3:
            return False
        
        if value.count(',') >= 2:
            return False
        
        return True
    
    
    def _validate_llm_finding(self, key: str, value: str) -> bool:
        if not value or not key:
            return False
        
        confidence = self.calculate_confidence(key, value)
        
        if confidence >= self.filter_threshold:
            return True
        else:
            logger.error(f"LLM finding rejected with low confidence: {confidence}")
            return False
    
    def adjust_confidence_with_heuristics(self, key: str, value: str) -> Tuple[float, bool]:
        confidence = self.calculate_confidence(key, value)
        should_filter = confidence < self.filter_threshold
        return confidence, should_filter
    
    def _validate_secret_value(self, value: str) -> Dict[str, Any]:
        result = {
            'is_valid': False,
            'reason': None
        }
        
        if not self._is_valid_secret(value):
            result['reason'] = 'Invalid secret format'
            return result
        
        confidence = self.calculate_confidence("", value)
        if confidence < self.filter_threshold:
            result['reason'] = f'Low confidence: {confidence}'
            return result
        
        result['is_valid'] = True
        return result
    
    def calculate_confidence(self, secret_key: str, secret_value: str, secret_type: Optional[str] = None) -> float:
        if not secret_value or len(secret_value) < self.min_secret_length:
            return 0.0
        
        value_lower = secret_value.lower()
        
        placeholder_patterns = [
            r'\b(test|demo|example|sample|dummy|fake|mock|staging|dev)\b',
            r'^(your|my|the)[\W_]?(password|secret|token|key)',
            r'(password|secret|token|key)123',
            r'^changeme$', r'^replaceme$', r'^todo$', r'^fixme$',
            r'^placeholder', r'^<[^>]+>$', r'^\$\{[^}]+\}$'
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, value_lower):
                return 0.1
        
        if len(set(secret_value)) <= 2:
            return 0.1
        
        entropy = self.calculate_entropy(secret_value)
        
        if entropy < 1.5:
            return 0.15
        elif entropy < 2.5:
            confidence = 0.3
        elif entropy < 3.5:
            confidence = 0.5
        elif entropy < 4.5:
            confidence = 0.7
        else:
            confidence = 0.85
        
        
        sequence_penalty = self._detect_sequences(secret_value)
        if sequence_penalty > 0:
            confidence = confidence * (1 - sequence_penalty)
        
        if any(secret_value.startswith(prefix) for prefix in self.known_prefixes):
            confidence = min(1.0, confidence + 0.2)
        
        key_lower = secret_key.lower() if secret_key else ""
        if any(kw in key_lower for kw in ['api', 'key', 'token', 'secret', 'password', 'auth']):
            confidence = min(1.0, confidence + 0.1)
        
        has_upper = any(c.isupper() for c in secret_value)
        has_lower = any(c.islower() for c in secret_value)
        has_digit = any(c.isdigit() for c in secret_value)
        has_special = any(not c.isalnum() for c in secret_value)
        complexity = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity >= 3:
            confidence = min(1.0, confidence + 0.1)
        
        return round(confidence, 2)
    
    def process_heuristic_only(self, added_lines: List[str], commit: git.Commit, 
                              file_path: str, report_generator: Any) -> int:
        heuristic_results = self.apply_regex_filters(added_lines)
        
        if heuristic_results:
            unique_count = 0
            duplicate_count = 0
            for heuristic_finding in heuristic_results:
                result = report_generator.add_heuristic_finding(commit, file_path, heuristic_finding)
                if result:
                    unique_count += 1
                else:
                    duplicate_count += 1
            
            if duplicate_count > 0:
                logger.info(f"Heuristic found {len(heuristic_results)} secret(s) in {file_path} ({unique_count} unique, {duplicate_count} duplicates filtered)")
            else:
                logger.info(f"Heuristic found {unique_count} unique secret(s) in {file_path}")
            return unique_count
        else:
            logger.info(f"No secrets found by heuristics in {file_path}")
            return 0
