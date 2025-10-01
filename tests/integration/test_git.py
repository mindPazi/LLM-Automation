import pytest
import git
from src.git_secret_scanner.git_handler import GitHandler


class TestRealGitIntegration:
    
    def setup_method(self):
        self.repo_path = "."
        self.git_handler = GitHandler(self.repo_path)
        
        
        try:
            self.repo = git.Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            pytest.skip("Not in a valid Git repository")
    
    def test_repository_initialization(self):
        
        assert self.git_handler.repo is not None
        assert self.git_handler.repo_path == "."
        
        
        assert hasattr(self.git_handler.repo, 'heads')
        
        try:
            branch = self.git_handler.repo.active_branch
            assert isinstance(branch.name, str)
        except TypeError:
            
            assert self.git_handler.repo.head.is_detached
    
    def test_get_recent_commits(self):
        
        commits = self.git_handler.get_recent_commits(3)
        
        
        assert isinstance(commits, list)
        assert len(commits) <= 3  
        
        if commits:
            for commit in commits:
                assert isinstance(commit, git.Commit)
                assert hasattr(commit, 'hexsha')
                assert hasattr(commit, 'author')
                assert hasattr(commit, 'message')
                assert len(commit.hexsha) == 40  
    
    def test_get_commit_range(self):
        
        recent_commits = self.git_handler.get_recent_commits(5)
        
        if len(recent_commits) < 2:
            pytest.skip("Need at least 2 commits for range test")
        
        
        single_commit = self.git_handler.get_commits_range(recent_commits[0].hexsha)
        assert len(single_commit) == 1
        assert single_commit[0].hexsha == recent_commits[0].hexsha
        
        
        from_commit = recent_commits[2].hexsha  
        to_commit = recent_commits[0].hexsha    
        
        range_commits = self.git_handler.get_commits_range(from_commit, to_commit)
        assert len(range_commits) >= 1
        
        
        commit_hashes = [c.hexsha for c in range_commits]
        assert to_commit in commit_hashes
        assert from_commit in commit_hashes
    
    def test_get_commit_changes(self):
        commits = self.git_handler.get_recent_commits(3)
        
        if not commits:
            pytest.skip("No commits available for testing")
        
        for commit in commits:
            changes = self.git_handler.get_commit_changes(commit)
            
            
            assert isinstance(changes, list)
            
            for change in changes:
                
                assert 'file_path' in change
                assert 'change_type' in change
                assert 'added_lines' in change
                assert 'removed_lines' in change
                
                
                assert isinstance(change['file_path'], str)
                
                
                assert isinstance(change['added_lines'], list)
                assert isinstance(change['removed_lines'], list)
                
                
                for line in change['added_lines']:
                    assert isinstance(line, str)
                for line in change['removed_lines']:
                    assert isinstance(line, str)
    
    def test_commit_diff_parsing(self):
        commits = self.git_handler.get_recent_commits(5)
        
        if not commits:
            pytest.skip("No commits available for testing")
        
        
        test_commit = None
        for commit in commits:
            if commit.parents:  
                changes = self.git_handler.get_commit_changes(commit)
                if changes and any(len(c['added_lines']) > 0 for c in changes):
                    test_commit = commit
                    break
        
        if not test_commit:
            pytest.skip("No commits with added lines found")
        
        changes = self.git_handler.get_commit_changes(test_commit)
        
        
        files_with_additions = [c for c in changes if len(c['added_lines']) > 0]
        assert len(files_with_additions) > 0, "Should have files with added lines"
        
        
        for change in files_with_additions:
            
            assert change['file_path'], "File path should not be empty"
            
            
            non_empty_lines = [line for line in change['added_lines'] if line.strip()]
            if non_empty_lines:  
                assert len(non_empty_lines) > 0, "Should have non-empty added lines"
    
    def test_repository_branch_and_remotes(self):
        
        try:
            current_branch = self.git_handler.repo.active_branch.name
            assert isinstance(current_branch, str)
            assert len(current_branch) > 0
        except TypeError:
            
            pass
        
        
        remotes = list(self.git_handler.repo.remotes)
        
        assert isinstance(remotes, list)
        
        for remote in remotes:
            assert hasattr(remote, 'name')
            assert hasattr(remote, 'url')
    
    def test_commit_author_and_date_parsing(self):
        commits = self.git_handler.get_recent_commits(2)
        
        if not commits:
            pytest.skip("No commits available for testing")
        
        for commit in commits:
            
            assert hasattr(commit, 'author')
            assert hasattr(commit.author, 'name')
            assert hasattr(commit.author, 'email')
            assert isinstance(commit.author.name, str)
            assert isinstance(commit.author.email, str)
            
            
            assert hasattr(commit, 'committed_datetime')
            assert commit.committed_datetime is not None
            
            
            assert hasattr(commit, 'message')
            assert isinstance(commit.message, str)
    
    def test_handling_empty_commits(self):
        commits = self.git_handler.get_recent_commits(10)
        
        if not commits:
            pytest.skip("No commits available for testing")
        
        
        for commit in commits:
            changes = self.git_handler.get_commit_changes(commit)
            
            
            assert isinstance(changes, list)
            
            
            if not changes:
                assert len(changes) == 0
            else:
                
                for change in changes:
                    assert isinstance(change, dict)
                    assert 'file_path' in change
    
    def test_error_handling_with_invalid_commits(self):
        
        with pytest.raises(Exception):
            self.git_handler.get_commits_range("invalid_commit_hash_12345")
        
        
        with pytest.raises(Exception):
            self.git_handler.get_commits_range("non_existent_branch_name")
