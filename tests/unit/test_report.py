
from unittest.mock import MagicMock
from src.git_secret_scanner.report import ReportGenerator


class TestReportGenerator:
    def setup_method(self):
        self.report = ReportGenerator()
        self.mock_commit = MagicMock()
        self.mock_commit.hexsha = "abc123def456"
        self.mock_commit.author = "Test Author"
        self.mock_commit.committed_datetime = "2024-01-01 12:00:00"
    
    def test_deduplication_llm_findings(self):
        secret1 = {'key': 'api_key', 'value': 'sk-proj-123456'}
        secret2 = {'key': 'api_key_copy', 'value': 'sk-proj-123456'}
        secret3 = {'key': 'another_key', 'value': 'different-value'}
        
        result1 = self.report.add_llm_finding(self.mock_commit, "file1.py", secret1, "gpt-5", category='raw')
        assert result1 is not None
        assert len(self.report.get_findings()) == 1
        assert self.report.llm_duplicates_count == 0
        
        result2 = self.report.add_llm_finding(self.mock_commit, "file1.py", secret2, "gpt-5", category='raw')
        assert result2 is None
        assert len(self.report.get_findings()) == 1
        assert self.report.llm_duplicates_count == 1
        assert self.report.duplicates_count == 1
        
        result3 = self.report.add_llm_finding(self.mock_commit, "file1.py", secret3, "gpt-5", category='raw')
        assert result3 is not None
        assert len(self.report.get_findings()) == 2
        assert self.report.llm_duplicates_count == 1
    
    def test_deduplication_heuristic_findings(self):
        finding1 = {
            'line_number': 10,
            'line': 'API_KEY=sk-123',
            'pattern_type': 'api_key',
            'secret_key': 'API_KEY',
            'secret_value': 'sk-123',
            'entropy': 3.5
        }
        
        
        finding2 = {
            'line_number': 20,
            'line': 'KEY=sk-123',
            'pattern_type': 'api_key',
            'secret_key': 'KEY',
            'secret_value': 'sk-123',
            'entropy': 3.5
        }
        
        
        finding3 = {
            'line_number': 10,
            'line': 'API_KEY=sk-123',
            'pattern_type': 'api_key',
            'secret_key': 'API_KEY',
            'secret_value': 'sk-123',
            'entropy': 3.5
        }
        
        result1 = self.report.add_heuristic_finding(self.mock_commit, "file.py", finding1)
        assert result1 is not None
        assert self.report.heuristic_duplicates_count == 0
        
        
        result2 = self.report.add_heuristic_finding(self.mock_commit, "file.py", finding2)
        assert result2 is not None
        assert self.report.heuristic_duplicates_count == 0
        
        
        result3 = self.report.add_heuristic_finding(self.mock_commit, "file.py", finding3)
        assert result3 is None
        assert self.report.heuristic_duplicates_count == 1
    
    def test_validated_llm_findings(self):
        secret = {'key': 'token', 'value': 'ghp_abc123', 'adjusted_confidence': 0.75}
        
        result = self.report.add_llm_finding(
            self.mock_commit, "file.py", secret, "gpt-5", category='validated'
        )
        
        assert result is not None
        assert result['finding_type'] == 'llm_validated_secret'
        assert len(self.report.get_findings()) == 1
    
    def test_false_positives_tracking(self):
        secret = {'key': 'test_key', 'value': 'test123'}
        
        result = self.report.add_llm_finding(
            self.mock_commit, "file.py", secret, "gpt-5", category='false_positive'
        )
        
        assert result is not None
        assert result['finding_type'] == 'llm_false_positive'
        assert len(self.report.get_findings()) == 0
        assert len(self.report.get_false_positives()) == 1
    
    def test_create_finding_structure(self):
        secret = {'key': 'api_key', 'value': 'sk-proj-123456'}
        
        finding = self.report._create_llm_finding(
            self.mock_commit, "test.py", secret, "gpt-5"
        )
        
        assert 'commit_hash' in finding
        assert 'author' in finding
        assert 'date' in finding
        assert 'file_path' in finding
        assert 'finding_type' in finding
        assert 'model' in finding
        assert 'secret_key' in finding
        assert 'secret_value' in finding
        assert 'confidence' in finding
        
        assert finding['commit_hash'] == "abc123def456"
        assert finding['file_path'] == "test.py"
        assert finding['model'] == "gpt-5"
        assert finding['secret_key'] == "api_key"
        assert finding['secret_value'] == "sk-proj-123456"
    
    def test_save_report(self, tmp_path):
        secret1 = {'key': 'key1', 'value': 'value1'}
        secret2 = {'key': 'key2', 'value': 'value2'}
        
        self.report.add_llm_finding(self.mock_commit, "file1.py", secret1, "gpt-5")
        self.report.add_llm_finding(self.mock_commit, "file2.py", secret2, "gpt-5")
        
        output_file = tmp_path / "test_report.json"
        saved_report = self.report.save_current_report(
            repository="test_repo",
            scan_mode="llm-only",
            commits_count=1,
            output_path=str(output_file)
        )
        
        assert output_file.exists()
        
        assert saved_report['repository'] == "test_repo"
        assert saved_report['scan_mode'] == "llm-only"
        assert saved_report['commits_scanned'] == 1
        assert len(saved_report['findings']) == 2
    
    def test_duplicates_across_commits(self):
        secret = {'key': 'api_key', 'value': 'sk-123'}
        
        mock_commit1 = MagicMock()
        mock_commit1.hexsha = "commit1"
        result1 = self.report.add_llm_finding(mock_commit1, "file.py", secret, "gpt-5", category='raw')
        assert result1 is not None
        
        mock_commit2 = MagicMock()
        mock_commit2.hexsha = "commit2"
        result2 = self.report.add_llm_finding(mock_commit2, "file.py", secret, "gpt-5", category='raw')
        assert result2 is not None
        
        assert len(self.report.get_findings()) == 2
        assert self.report.duplicates_count == 0
    
    def test_duplicates_across_files(self):
        secret = {'key': 'api_key', 'value': 'sk-123'}
        
        result1 = self.report.add_llm_finding(self.mock_commit, "file1.py", secret, "gpt-5", category='raw')
        assert result1 is not None
        
        result2 = self.report.add_llm_finding(self.mock_commit, "file2.py", secret, "gpt-5", category='raw')
        assert result2 is not None
        
        assert len(self.report.get_findings()) == 2
        assert self.report.duplicates_count == 0
