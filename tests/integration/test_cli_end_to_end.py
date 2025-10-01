import pytest
import subprocess
import json
import os
import tempfile


class TestCLIEndToEnd:
    
    def test_cli_heuristic_only_mode(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            result = subprocess.run([
                'python', '-m', 'src.git_secret_scanner.cli',
                '--repo', '.',
                '--last', '2',
                '--mode', 'heuristic-only',
                '--out', output_file,
                '--log-level', 'ERROR'
            ], capture_output=True, text=True, timeout=60)
            
            assert result.returncode == 0, f"CLI failed: {result.stderr}"
            assert os.path.exists(output_file), "Output file was not created"
            
            with open(output_file, 'r') as f:
                report = json.load(f)
            
            assert 'repository' in report
            assert 'scan_mode' in report
            assert 'commits_scanned' in report
            assert 'findings' in report
            assert report['scan_mode'] == 'heuristic-only'
            assert report['commits_scanned'] == 2
            
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_cli_commit_range(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            get_commits = subprocess.run([
                'git', 'log', '--oneline', '-n', '3', '--format=%H'
            ], capture_output=True, text=True, cwd='.')
            
            commits = get_commits.stdout.strip().split('\n')
            assert len(commits) >= 2, "Need at least 2 commits for range test"
            
            from_commit = commits[1]
            to_commit = commits[0]
            
            result = subprocess.run([
                'python', '-m', 'src.git_secret_scanner.cli',
                '--repo', '.',
                '--from', from_commit,
                '--to', to_commit,
                '--mode', 'heuristic-only',
                '--out', output_file,
                '--log-level', 'ERROR'
            ], capture_output=True, text=True, timeout=60)
            
            assert result.returncode == 0, f"CLI failed: {result.stderr}"
            
            with open(output_file, 'r') as f:
                report = json.load(f)
            
            assert report['commits_scanned'] >= 1
            assert report['scan_mode'] == 'heuristic-only'
            
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_cli_invalid_parameters(self):
        result = subprocess.run([
            'python', '-m', 'src.git_secret_scanner.cli',
            '--repo', '.',
            '--mode', 'heuristic-only'
        ], capture_output=True, text=True)
        
        assert result.returncode != 0, "CLI should fail without --last or --from"
        assert "Either --last n or --from commit is required" in result.stderr
    
    def test_cli_log_levels(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            result = subprocess.run([
                'python', '-m', 'src.git_secret_scanner.cli',
                '--repo', '.',
                '--last', '1',
                '--mode', 'heuristic-only',
                '--out', output_file,
                '--log-level', 'DEBUG'
            ], capture_output=True, text=True, timeout=60)
            
            assert result.returncode == 0
            assert "DEBUG" in result.stderr or "Processing" in result.stderr
            
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_cli_custom_output_file(self):
        custom_output_dir = tempfile.mkdtemp()
        custom_output_file = os.path.join(custom_output_dir, 'custom_report.json')
        
        try:
            result = subprocess.run([
                'python', '-m', 'src.git_secret_scanner.cli',
                '--repo', '.',
                '--last', '1',
                '--mode', 'heuristic-only',
                '--out', custom_output_file,
                '--log-level', 'ERROR'
            ], capture_output=True, text=True, timeout=60)
            
            assert result.returncode == 0
            assert os.path.exists(custom_output_file)
            
            with open(custom_output_file, 'r') as f:
                report = json.load(f)
                assert isinstance(report, dict)
                
        finally:
            if os.path.exists(custom_output_file):
                os.unlink(custom_output_file)
            if os.path.exists(custom_output_dir):
                os.rmdir(custom_output_dir)
    
    @pytest.mark.skipif(not os.getenv('OPENAI_API_KEY'), reason="OpenAI API key not available")
    def test_cli_llm_mode_with_api_key(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            result = subprocess.run([
                'python', '-m', 'src.git_secret_scanner.cli',
                '--repo', '.',
                '--last', '1',
                '--mode', 'llm-only',
                '--out', output_file,
                '--log-level', 'ERROR'
            ], capture_output=True, text=True, timeout=120)
            
            assert result.returncode == 0, f"LLM mode failed: {result.stderr}"
            
            with open(output_file, 'r') as f:
                report = json.load(f)
            
            assert report['scan_mode'] == 'llm-only'
            
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
