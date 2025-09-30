import pytest
from unittest.mock import MagicMock, patch
from src.git_secret_scanner.git_handler import GitHandler


class TestGitHandler:
    @patch('git.Repo')
    def test_init_valid_repo(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        handler = GitHandler("/path/to/repo")
        
        assert handler.repo == mock_repo
        mock_repo_class.assert_called_once_with("/path/to/repo")
    
    @patch('git.Repo')
    def test_init_invalid_repo(self, mock_repo_class):
        mock_repo_class.side_effect = Exception("Invalid repository")
        
        with pytest.raises(Exception):
            GitHandler("/invalid/path")
    
    @patch('git.Repo')
    def test_get_recent_commits(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commits = [MagicMock() for _ in range(3)]
        mock_repo.iter_commits.return_value = mock_commits
        
        handler = GitHandler("/path/to/repo")
        commits = handler.get_recent_commits(3)
        
        assert len(commits) == 3
        mock_repo.iter_commits.assert_called_once_with(max_count=3)
    
    @patch('git.Repo')
    def test_get_commits_range_single(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_repo.iter_commits.return_value = [mock_commit]
        
        handler = GitHandler("/path/to/repo")
        commits = handler.get_commits_range("abc123")
        
        assert commits == [mock_commit]
        mock_repo.iter_commits.assert_called_once_with("abc123^..abc123")
    
    @patch('git.Repo')
    def test_get_commits_range_between(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commits = [MagicMock() for _ in range(10)]
        mock_repo.iter_commits.return_value = mock_commits
        
        handler = GitHandler("/path/to/repo")
        commits = handler.get_commits_range("abc123", "def456")
        
        assert commits == mock_commits
        
        mock_repo.iter_commits.assert_called_once_with("abc123^..def456")
    
    @patch('git.Repo')
    def test_get_commit_changes(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_commit.parents = [MagicMock()]
        
        mock_diff_item = MagicMock()
        mock_diff_item.a_path = None
        mock_diff_item.b_path = "new_file.py"
        mock_diff_item.diff = b"""
+API_KEY = "sk-proj-123456"
+password = "MySecretPassword123"
-old_line = "removed"
 unchanged_line = "same"
+another_secret = "ghp_abc123"
"""
        
        mock_commit.parents[0].diff.return_value = [mock_diff_item]
        
        handler = GitHandler("/path/to/repo")
        changes = handler.get_commit_changes(mock_commit)
        
        assert len(changes) == 1
        change = changes[0]
        
        assert change['file_path'] == "new_file.py"
        assert len(change['added_lines']) == 3
        assert 'API_KEY = "sk-proj-123456"' in change['added_lines'][0]
        assert 'password = "MySecretPassword123"' in change['added_lines'][1]
        assert 'another_secret = "ghp_abc123"' in change['added_lines'][2]
    
    @patch('git.Repo')
    def test_get_commit_changes_modified_file(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_commit.parents = [MagicMock()]
        
        mock_diff_item = MagicMock()
        mock_diff_item.a_path = "existing_file.py"
        mock_diff_item.b_path = "existing_file.py"
        mock_diff_item.diff = b"""
@@ -10,3 +10,5 @@
 context_line = "unchanged"
+new_secret = "token123"
+api_key = "key456"
"""
        
        mock_commit.parents[0].diff.return_value = [mock_diff_item]
        
        handler = GitHandler("/path/to/repo")
        changes = handler.get_commit_changes(mock_commit)
        
        assert len(changes) == 1
        assert changes[0]['file_path'] == "existing_file.py"
        assert len(changes[0]['added_lines']) == 2
    
    @patch('git.Repo')
    def test_get_commit_changes_deleted_file(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_commit.parents = [MagicMock()]
        
        mock_diff_item = MagicMock()
        mock_diff_item.a_path = "deleted_file.py"
        mock_diff_item.b_path = None
        mock_diff_item.diff = b"-removed_line"
        
        mock_commit.parents[0].diff.return_value = [mock_diff_item]
        
        handler = GitHandler("/path/to/repo")
        changes = handler.get_commit_changes(mock_commit)
        
        assert len(changes) == 1
        assert changes[0]['file_path'] == "deleted_file.py"
        assert len(changes[0]['removed_lines']) == 1
    
    @patch('git.Repo')
    def test_get_commit_changes_binary_file(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_commit.parents = [MagicMock()]
        
        mock_diff_item = MagicMock()
        mock_diff_item.a_path = None
        mock_diff_item.b_path = "image.png"
        mock_diff_item.diff = None
        
        mock_commit.parents[0].diff.return_value = [mock_diff_item]
        
        handler = GitHandler("/path/to/repo")
        changes = handler.get_commit_changes(mock_commit)
        
        assert len(changes) == 1
        assert changes[0]['file_path'] == "image.png"
        assert changes[0]['added_lines'] == []
    
    @patch('git.Repo')
    def test_get_commit_changes_initial_commit(self, mock_repo_class):
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_commit = MagicMock()
        mock_commit.parents = []
        
        mock_diff_item = MagicMock()
        mock_diff_item.a_path = None
        mock_diff_item.b_path = "initial_file.py"
        mock_diff_item.diff = b"+initial_content"
        
        mock_commit.diff.return_value = [mock_diff_item]
        
        handler = GitHandler("/path/to/repo")
        changes = handler.get_commit_changes(mock_commit)
        
        assert len(changes) == 1
        assert changes[0]['file_path'] == "initial_file.py"
