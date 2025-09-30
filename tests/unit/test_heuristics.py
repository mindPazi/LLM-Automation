import pytest
from src.git_secret_scanner.heuristics import HeuristicFilter


class TestHeuristicFilter:
    def setup_method(self):
        self.filter = HeuristicFilter()
    
    def test_entropy_calculation(self):
        assert self.filter.calculate_entropy("aaaaaaa") < 1.0
        
        random_string = "aB3$xY9!pQ2&mN5"
        assert self.filter.calculate_entropy(random_string) > 3.0
        
        assert self.filter.calculate_entropy("") == 0.0
        
        assert self.filter.calculate_entropy("a") == 0.0
    
    def test_is_valid_secret(self):
        assert self.filter._is_valid_secret("sk-proj-abc123XYZ789") == True
        
        assert self.filter._is_valid_secret("abc") == False
        
        assert self.filter._is_valid_secret("${ENV_VAR}") == False
        assert self.filter._is_valid_secret("%(ENV_VAR)s") == False
        assert self.filter._is_valid_secret("{{ENV_VAR}}") == False
        
        assert self.filter._is_valid_secret("test") == False
        
        assert self.filter._is_valid_secret("your_password_here") == True
        
        assert self.filter._is_valid_secret("changeme") == True
        
        assert self.filter._is_valid_secret("this has too many spaces in it") == False
    
    def test_validate_llm_finding(self):
        assert self.filter.validate_llm_finding("api_key", "sk-proj-abc123XYZ789def456") == True
        
        assert self.filter.validate_llm_finding("", "sk-proj-abc123XYZ789def456") == False
        
        assert self.filter.validate_llm_finding("api_key", "") == False
        
        
        
        assert self.filter.validate_llm_finding("config", "val1,val2,val3") == True
        
        
        assert self.filter.validate_llm_finding("key", "this has way too many spaces in the text") == True
    
    def test_calculate_confidence(self):
        confidence = self.filter.calculate_confidence("api_key", "sk-proj-abc123XYZ789", "api_key")
        assert confidence > 0.5
        
        confidence = self.filter.calculate_confidence("password", "simple", "password")
        assert confidence <= 0.8
        
        
        confidence = self.filter.calculate_confidence("config", "val", None)
        assert confidence == 0.0
        
        
        
        confidence = self.filter.calculate_confidence("text", "this has way too many spaces in it", None)
        assert confidence == 0.7
    
    def test_adjust_confidence_with_heuristics(self):
        initial = 0.8
        adjusted, should_filter = self.filter.adjust_confidence_with_heuristics(
            initial, "secret", "test"
        )
        assert adjusted < initial
        assert should_filter == True
        
        initial = 0.5
        adjusted, should_filter = self.filter.adjust_confidence_with_heuristics(
            initial, "github_token", "ghp_abc123XYZ789"
        )
        assert adjusted >= initial
        
        initial = 0.6
        adjusted, should_filter = self.filter.adjust_confidence_with_heuristics(
            initial, "key", "aaaaaaaa"
        )
        assert adjusted < initial
    
    def test_apply_regex_filters(self):
        content = """
        API_KEY=sk-proj-abc123XYZ789def456
        password: MySecretPass123!
        token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        """
        
        findings = self.filter.apply_regex_filters(content)
        assert len(findings) > 0
        
        for finding in findings:
            assert 'line_number' in finding
            assert 'line' in finding
            assert 'pattern_type' in finding
            assert 'secret_key' in finding
            assert 'secret_value' in finding
            assert 'entropy' in finding
    
    def test_apply_filters(self):
        potential_issues = [
            {'secret_value': 'sk-proj-abc123XYZ789def456'},
            {'secret_value': 'test'},
            {'secret_value': 'changeme'},
            {'secret_value': 'ghp_1234567890abcdef'},
        ]
        
        filtered = self.filter.apply_filters(potential_issues)
        assert len(filtered) == 2
        
        for issue in filtered:
            assert issue['secret_value'] not in ['test', 'changeme']
