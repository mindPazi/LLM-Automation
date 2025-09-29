import re
import math
from typing import List, Dict, Any, Tuple, Optional
from collections import Counter
from src.git_secret_scanner.config_loader import config
from src.git_secret_scanner.logger_config import get_logger

logger = get_logger(__name__)

class HeuristicFilter:
    
    def __init__(self) -> None:
        logger.info("Initializing HeuristicFilter")
        
        self.entropy_threshold = config.get('heuristics', 'entropy', 'threshold', default=3.5)
        self.min_entropy = config.get('heuristics', 'entropy', 'min_entropy', default=2.5)
        self.low_entropy_cutoff = config.get('heuristics', 'entropy', 'low_entropy_cutoff', default=2.5)
        self.medium_entropy_cutoff = config.get('heuristics', 'entropy', 'medium_entropy_cutoff', default=4.0)
        
        
        self.min_secret_length = config.get('validation', 'min_secret_length', default=8)
        self.min_comma_count = config.get('validation', 'min_comma_count', default=2)
        self.max_spaces = config.get('validation', 'max_spaces', default=3)
        self.max_space_count = config.get('validation', 'max_space_count', default=2)
        
        self.comma_keywords = config.get('validation', 'comma_keywords', 
            default=['password', 'secret', 'token', 'key', 'api', 'auth', 'credential', 'private'])
        self.min_keyword_count_for_fp = config.get('validation', 'min_keyword_count_for_fp', default=3)
        
        self.test_values = config.get('validation', 'test_values', 
            default=['test', 'example', 'sample', 'demo', 'dummy', 'fake', 'mock',
             'your_password_here', 'your_secret_here', 'your_token_here',
             'your_key_here', 'your_api_key_here', 'changeme', 'replaceme',
             '<password>', '<secret>', '<token>', '<key>', '<api_key>'])
        
        self.internal_patterns = config.get('validation', 'internal_patterns',
            default=['_secret_', '_test_', '_demo_', '_example_', '_sample_'])
        self.additional_patterns = config.get('validation', 'additional_patterns',
            default=['test_', 'demo_', 'example_', 'sample_', 'dummy_', 'fake_', 'mock_'])
        
        self.placeholders = config.get('validation', 'placeholders',
            default=['xxx', 'yyy', 'zzz', '***', '...', '___', 'todo', 'fixme', 
             'placeholder', 'replace', 'your-', 'my-', '<', '>'])
        
        self.strong_keywords = config.get('validation', 'strong_keywords',
            default=['api_key', 'api-key', 'apikey', 'secret_key', 'secret-key', 'secretkey',
             'private_key', 'private-key', 'privatekey', 'access_token', 'access-token',
             'accesstoken', 'auth_token', 'auth-token', 'authtoken'])
        
        self.entropy_threshold_no_keyword = config.get('validation', 'entropy_threshold_no_keyword', default=4.5)
        
        self.known_prefixes = config.get('validation', 'known_prefixes', 
            default=['sk-', 'pk-', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'])
        self.token_suffixes = config.get('validation', 'token_suffixes', 
            default=['_token', '_key', '_secret', '_pass', '_pwd'])
        self.pem_markers = config.get('validation', 'pem_markers', 
            default=['-----BEGIN', '-----END'])
        self.pem_prefixes = config.get('validation', 'pem_prefixes', 
            default=['-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----',
             '-----BEGIN EC PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----',
             '-----BEGIN DSA PRIVATE KEY-----', '-----BEGIN CERTIFICATE-----',
             '-----END PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'])
        
        self.code_literals = config.get('validation', 'code_literals',
            default=['true', 'false', 'null', 'none', 'undefined'])
        self.weak_patterns = config.get('validation', 'weak_patterns',
            default=['temp', 'tmp', 'test', 'debug'])
        
        
        self.confidence_return_comma = config.get('validation', 'confidence_return_comma', default=0.2)
        self.confidence_return_spaces = config.get('validation', 'confidence_return_spaces', default=0.15)
        self.confidence_return_min = config.get('validation', 'confidence_return_min', default=0.05)
        
        
        self.min_length_short = config.get('validation', 'min_length_short', default=6)
        self.max_length_long = config.get('validation', 'max_length_long', default=100)
        
        
        self.entropy_very_low = config.get('validation', 'entropy_very_low', default=2.0)
        self.entropy_high = config.get('validation', 'entropy_high', default=5.0)
        
        
        self.mult_dash_pattern = config.get('heuristics', 'multipliers', 'dash_pattern', default=0.4)
        self.mult_uppercase_underscore = config.get('heuristics', 'multipliers', 'uppercase_underscore', default=0.5)
        self.mult_lowercase_underscore = config.get('heuristics', 'multipliers', 'lowercase_underscore', default=0.6)
        self.mult_code_literal = config.get('heuristics', 'multipliers', 'code_literal', default=0.3)
        self.mult_low_entropy = config.get('heuristics', 'multipliers', 'low_entropy', default=0.5)
        self.mult_medium_entropy = config.get('heuristics', 'multipliers', 'medium_entropy', default=0.8)
        self.mult_pem_marker = config.get('heuristics', 'multipliers', 'pem_marker', default=0.2)
        self.mult_test_value = config.get('heuristics', 'multipliers', 'test_value', default=0.1)
        self.mult_internal_test_pattern = config.get('heuristics', 'multipliers', 'internal_test_pattern', default=0.2)
        self.mult_comma_separated = config.get('heuristics', 'multipliers', 'comma_separated', default=0.3)
        self.mult_space_heavy = config.get('heuristics', 'multipliers', 'space_heavy', default=0.2)
        self.mult_very_low_entropy = config.get('heuristics', 'multipliers', 'very_low_entropy', default=0.3)
        self.mult_high_entropy_boost = config.get('heuristics', 'multipliers', 'high_entropy_boost', default=1.3)
        self.mult_weak_pattern = config.get('heuristics', 'multipliers', 'weak_pattern', default=0.4)
        self.mult_known_pattern_boost = config.get('heuristics', 'multipliers', 'known_pattern_boost', default=1.5)
        self.mult_strong_keyword_boost = config.get('heuristics', 'multipliers', 'strong_keyword_boost', default=1.3)
        self.mult_short_value = config.get('heuristics', 'multipliers', 'short_value', default=0.5)
        self.mult_long_value = config.get('heuristics', 'multipliers', 'long_value', default=0.7)
        
        
        self.filter_threshold = config.get('heuristics', 'confidence', 'filter_threshold', default=0.25)
        self.base_confidence = config.get('heuristics', 'confidence', 'base_confidence', default=0.3)
        
        
        
        entropy_scores = config.get('scoring', 'entropy_scores', default=[
            {'threshold': 5.5, 'score': 0.4},
            {'threshold': 4.5, 'score': 0.35},
            {'threshold': 3.5, 'score': 0.25},
            {'threshold': 2.5, 'score': 0.15},
            {'threshold': 0, 'score': 0.05}
        ])
        self.entropy_score_thresholds = [(s['threshold'], s['score']) for s in entropy_scores]
        
        
        length_scores = config.get('scoring', 'length_scores', default=[
            {'min': 32, 'max': 64, 'score': 0.2},
            {'min': 16, 'max': 31, 'score': 0.15},
            {'min': 8, 'max': 15, 'score': 0.1},
            {'min': 0, 'max': 7, 'score': 0.05}
        ])
        self.length_score_ranges = [(s['min'], s['max'], s['score']) for s in length_scores]
        
        
        type_scores = config.get('scoring', 'type_scores', default={
            'known_pattern': 0.25,
            'api_key': 0.2,
            'token': 0.18,
            'password': 0.15,
            'secret': 0.12,
            'default': 0.05
        })
        self.type_score_known = type_scores.get('known_pattern', 0.25)
        self.type_score_api = type_scores.get('api_key', 0.2)
        self.type_score_token = type_scores.get('token', 0.18)
        self.type_score_password = type_scores.get('password', 0.15)
        self.type_score_secret = type_scores.get('secret', 0.12)
        self.type_score_default = type_scores.get('default', 0.05)
        
        
        complexity_scores = config.get('scoring', 'complexity_scores', default={
            'all_types': 0.2,
            'three_types': 0.15,
            'two_types': 0.1,
            'one_type': 0.05
        })
        self.complexity_all = complexity_scores.get('all_types', 0.2)
        self.complexity_three = complexity_scores.get('three_types', 0.15)
        self.complexity_two = complexity_scores.get('two_types', 0.1)
        self.complexity_one = complexity_scores.get('one_type', 0.05)
        
        
        patterns_config = config.get('patterns', 'secret_patterns', default=[])
        self.secret_patterns = []
        for pattern_dict in patterns_config:
            if isinstance(pattern_dict, dict) and 'pattern' in pattern_dict and 'type' in pattern_dict:
                self.secret_patterns.append((pattern_dict['pattern'], pattern_dict['type']))
        
        self.known_patterns = config.get('patterns', 'known_patterns', default={})
        
        logger.debug(f"Loaded {len(self.secret_patterns)} secret patterns")
        logger.debug(f"Loaded {len(self.known_patterns)} known patterns")
        logger.info("HeuristicFilter initialized successfully")
    
    def apply_filters(self, potential_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.debug(f"Applying filters to {len(potential_issues)} potential issues")
        filtered_issues = []
        
        for issue in potential_issues:
            if 'secret_value' in issue:
                value = issue['secret_value']
                validation_result = self._validate_secret_value(value)
                
                if validation_result['is_valid']:
                    logger.debug(f"Valid secret: {issue.get('secret_key', 'unknown')[:20]}...")
                    filtered_issues.append(issue)
                else:
                    logger.debug(f"Filtered out: {validation_result.get('reason', 'unknown reason')}")
            else:
                filtered_issues.append(issue)
        
        logger.debug(f"Filtered to {len(filtered_issues)} valid issues")
        return filtered_issues
    
    def apply_regex_filters(self, content: Any) -> List[Dict[str, Any]]:
        logger.debug("Starting regex filter analysis")
        findings = []
        
        lines = content.split('\n') if isinstance(content, str) else content
        logger.debug(f"Processing {len(lines)} lines")
        
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
                        entropy = self.calculate_entropy(value)
                        logger.debug(f"Found potential secret on line {line_num}: {key[:20]}... (entropy: {entropy:.2f})")
                        findings.append({
                            'line_number': line_num,
                            'line': line[:200],  
                            'pattern_type': pattern_type,
                            'secret_key': key,
                            'secret_value': value[:50] + "..." if len(value) > 50 else value,
                            'entropy': entropy
                        })
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
    
    def _is_valid_secret(self, value: str) -> bool:
        if not value or len(value) < self.min_secret_length:
            logger.debug(f"Secret too short: {len(value) if value else 0} < {self.min_secret_length}")
            return False
        
        if value.startswith("${") or value.startswith("%(") or value.startswith("{{"):
            logger.debug(f"Environment variable pattern detected: {value[:10]}...")
            return False
        
        if ',' in value and value.count(',') >= self.min_comma_count:
            words = [w.strip() for w in value.split(',')]
            keyword_count = sum(1 for w in words if any(kw in w.lower() for kw in self.comma_keywords))
            if keyword_count >= self.min_keyword_count_for_fp:
                return False
        
        if value.count(' ') > self.max_spaces:
            return False
        
        if value.lower() in self.test_values:
            logger.debug(f"Test value detected: {value[:20]}...")
            return False
        
        value_lower = value.lower()
        if any(pattern in value_lower for pattern in self.internal_patterns):
            return False
        
        return True
    
    def _is_placeholder(self, value: str) -> bool:
        value_lower = value.lower()
        for placeholder in self.placeholders:
            if placeholder in value_lower:
                return True
        
        return False
    
    def validate_llm_finding(self, key: str, value: str) -> bool:
        logger.debug(f"Validating LLM finding: {key[:20] if key else 'no-key'}...")
        
        if not value or not key:
            logger.debug("Missing key or value")
            return False
        
        if ',' in value and value.count(',') >= self.min_comma_count:
            return False
        
        if value.count(' ') > self.max_spaces:
            return False
        
        validation_result = self._validate_secret_value(value, min_entropy=self.min_entropy)
        if not validation_result['is_valid']:
            return False
        
        key_lower = key.lower()
        has_secret_keyword = any(keyword in key_lower for keyword in self.strong_keywords)
        
        if not has_secret_keyword and validation_result['entropy'] < self.entropy_threshold_no_keyword:
            logger.debug(f"No keyword and low entropy: {validation_result['entropy']:.2f} < {self.entropy_threshold_no_keyword}")
            return False
        
        logger.debug("LLM finding validated successfully")
        return True
    
    def adjust_confidence_with_heuristics(self, initial_confidence: float, key: str, value: str) -> Tuple[float, bool]:
        logger.debug(f"Adjusting confidence for {key[:20] if key else 'no-key'}... (initial: {initial_confidence:.2f})")
        confidence = initial_confidence
        
        
        if '-' in value and not any(value.startswith(prefix) for prefix in self.known_prefixes):
            if any(char.isdigit() for char in value) or value.count('-') >= 2:
                confidence *= self.mult_dash_pattern
        
        
        if '_' in value and value.isupper():
            confidence *= self.mult_uppercase_underscore
        elif '_' in value and not any(char.isupper() for char in value):
            if any(value.endswith(suffix) for suffix in self.token_suffixes):
                confidence *= self.mult_lowercase_underscore
        
        
        if any(value.lower() == literal or value.lower().endswith(f'_{literal}') for literal in self.code_literals):
            confidence *= self.mult_code_literal
        
        
        entropy = self.calculate_entropy(value)
        if entropy < self.low_entropy_cutoff:
            confidence *= self.mult_low_entropy
        elif entropy < self.medium_entropy_cutoff:
            confidence *= self.mult_medium_entropy
        
        
        if value in self.pem_markers or any(value.startswith(prefix) for prefix in self.pem_prefixes):
            confidence *= self.mult_pem_marker
        
        
        value_lower = value.lower()
        if value_lower in self.test_values:
            confidence *= self.mult_test_value
        
        
        if any(pattern in value_lower for pattern in self.internal_patterns) or \
           any(pattern in value_lower for pattern in self.additional_patterns):
            confidence *= self.mult_internal_test_pattern
        
        if ',' in value and value.count(',') >= 1:
            confidence *= self.mult_comma_separated
        
        if value.count(' ') > self.max_space_count:
            confidence *= self.mult_space_heavy
        
        
        if entropy < self.entropy_very_low:
            confidence *= self.mult_very_low_entropy
        elif entropy > self.entropy_high:
            confidence *= self.mult_high_entropy_boost
        
        
        if any(pattern in value_lower for pattern in self.weak_patterns):
            confidence *= self.mult_weak_pattern
        
        
        is_test_value = any(test_val in value_lower for test_val in self.test_values)
        if not is_test_value:
            for pattern_name, pattern in self.known_patterns.items():
                if re.match(pattern, value):
                    confidence *= self.mult_known_pattern_boost
                    break
        
        
        key_lower = key.lower() if key else ""
        if any(kw in key_lower for kw in self.strong_keywords):
            if not is_test_value and value not in self.pem_markers:
                confidence *= self.mult_strong_keyword_boost
        
        
        if len(value) < self.min_length_short:
            confidence *= self.mult_short_value
        elif len(value) > self.max_length_long:
            confidence *= self.mult_long_value
        
        confidence = min(1.0, max(0.0, confidence))
        
        should_filter = confidence < self.filter_threshold
        
        logger.debug(f"Final confidence: {confidence:.2f}, filter: {should_filter}")
        return confidence, should_filter
    
    def _validate_secret_value(self, value: str, min_entropy: float = None) -> Dict[str, Any]:
        if min_entropy is None:
            min_entropy = self.min_entropy
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
    
    def calculate_confidence(self, secret_key: str, secret_value: str, secret_type: Optional[str] = None) -> float:
        if ',' in secret_value and secret_value.count(',') >= self.min_comma_count:
            return self.confidence_return_comma
        
        if secret_value.count(' ') > self.max_spaces:
            return self.confidence_return_spaces
        
        
        entropy_score = self._calculate_entropy_score(secret_value)
        length_score = self._calculate_length_score(secret_value)
        type_score = self._calculate_type_score(secret_key, secret_value, secret_type)
        complexity_score = self._calculate_complexity_score(secret_value)
        
        total_score = self.base_confidence + entropy_score + length_score + type_score + complexity_score
        
        return min(1.0, max(self.confidence_return_min, total_score))
    
    def _calculate_entropy_score(self, value: str) -> float:
        entropy = self.calculate_entropy(value)
        
        for threshold, score in self.entropy_score_thresholds:
            if entropy > threshold:
                return score
        
        return self.entropy_score_thresholds[-1][1]  
    
    def _calculate_length_score(self, value: str) -> float:
        length = len(value)
        
        for min_len, max_len, score in self.length_score_ranges:
            if min_len <= length <= max_len:
                return score
        
        return self.length_score_ranges[-1][2]  
    
    def _calculate_type_score(self, key: str, value: str, secret_type: Optional[str] = None) -> float:
        
        for pattern_name, pattern in self.known_patterns.items():
            if re.match(pattern, value):
                return self.type_score_known
        
        key_lower = key.lower() if key else ""
        
        if 'api' in key_lower and 'key' in key_lower:
            return self.type_score_api
        elif 'token' in key_lower or 'bearer' in value.lower():
            return self.type_score_token
        elif 'password' in key_lower or 'pass' in key_lower:
            return self.type_score_password
        elif 'secret' in key_lower or 'key' in key_lower:
            return self.type_score_secret
        else:
            return self.type_score_default
    
    def _calculate_complexity_score(self, value: str) -> float:
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(not c.isalnum() for c in value)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_count == 4:
            return self.complexity_all
        elif complexity_count == 3:
            return self.complexity_three
        elif complexity_count == 2:
            return self.complexity_two
        else:
            return self.complexity_one
