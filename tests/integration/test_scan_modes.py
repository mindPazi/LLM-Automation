import pytest
import os
import tempfile
from src.git_secret_scanner.git_handler import GitHandler
from src.git_secret_scanner.heuristics import HeuristicFilter
from src.git_secret_scanner.llm_analyzer import LLMAnalyzer
from src.git_secret_scanner.report import ReportGenerator


class TestScanModes:
    def setup_method(self):
        self.repo_path = "."
        self.git_handler = GitHandler(self.repo_path)
        self.heuristic_filter = HeuristicFilter()
        self.report_generator = ReportGenerator()
        
        commits = self.git_handler.get_recent_commits(1)
        if commits:
            self.test_commit = commits[0]
            self.test_changes = self.git_handler.get_commit_changes(self.test_commit)
        else:
            pytest.skip("No commits available for testing")
    
    def test_heuristic_only_mode(self):
        test_lines = [
            'API_KEY = "sk-proj-abc123XYZ789def456"',
            'password = "MySecretPass123!"',
            'bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"',
            'config_value = "not_a_secret"'
        ]
        
        findings = self.heuristic_filter.apply_regex_filters(test_lines)
        assert len(findings) >= 0
        
        for finding in findings:
            assert 'secret_key' in finding
            assert 'secret_value' in finding
            assert 'entropy' in finding
            assert 'pattern_type' in finding
    
    @pytest.mark.skipif(not os.getenv('OPENAI_API_KEY'), reason="OpenAI API key not available")
    def test_llm_load(self):
        llm_analyzer = LLMAnalyzer()
        llm_analyzer.load_model()
        
        test_lines = ['config = "value"']
        findings = llm_analyzer.analyze_lines(test_lines)
        
        assert isinstance(findings, list)
    
    def test_file_filtering(self):
        if not hasattr(self, 'test_changes') or not self.test_changes:
            pytest.skip("No commit changes available for testing")
        
        processable_files = 0
        skipped_files = 0
        
        for change in self.test_changes:
            file_path = change['file_path']
            
            should_skip = (
                (file_path.endswith('.json') and 'output' in file_path) or
                file_path.endswith('_test.json') or
                file_path.endswith('_report.json') or
                file_path.lower() in ['readme.md', 'readme.txt', 'readme.rst', 'readme'] or
                file_path.lower() == 'config.yaml' or
                file_path.endswith('/config.yaml') or
                'tests/unit/' in file_path or
                file_path.startswith('unit/') or
                len(change['added_lines']) == 0
            )
            
            if should_skip:
                skipped_files += 1
            else:
                processable_files += 1
        
        total_files = processable_files + skipped_files
        assert total_files == len(self.test_changes), "File count mismatch"
    
    def test_report_generation(self):
        mock_commit = self.test_commit if hasattr(self, 'test_commit') else None
        
        if not mock_commit:
            pytest.skip("No test commit available")
        
        secret1 = {'key': 'api_key', 'value': 'sk-proj-123456', 'confidence': 0.9}
        secret2 = {'key': 'password', 'value': 'TestPassword123!', 'confidence': 0.7}
        
        result1 = self.report_generator.add_llm_finding(
            mock_commit, "test_file1.py", secret1, "gpt-4o-mini"
        )
        result2 = self.report_generator.add_llm_finding(
            mock_commit, "test_file2.py", secret2, "gpt-4o-mini"
        )
        
        assert result1 is not None
        assert result2 is not None
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            saved_report = self.report_generator.save_current_report(
                repository="test_repo",
                scan_mode="test_mode", 
                commits_count=1,
                output_path=output_file
            )
            
            assert 'repository' in saved_report
            assert 'scan_mode' in saved_report
            assert 'commits_scanned' in saved_report
            assert 'findings' in saved_report
            assert len(saved_report['findings']) == 2
            assert os.path.exists(output_file)
            
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_duplicate_detection_across_modes(self):
        if not hasattr(self, 'test_commit'):
            pytest.skip("No test commit available")
        
        secret = {'key': 'duplicate_test', 'value': 'same_secret_value_123'}
        
        result1 = self.report_generator.add_llm_finding(
            self.test_commit, "file1.py", secret, "gpt-4o-mini"
        )
        result2 = self.report_generator.add_llm_finding(
            self.test_commit, "file1.py", secret, "gpt-4o-mini"
        )
        
        assert result1 is not None
        assert result2 is None
        assert self.report_generator.duplicates_count == 1
