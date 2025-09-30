import git
from typing import List, Optional, Dict, Any
from src.git_secret_scanner.logger_config import get_logger

logger = get_logger(__name__)

class GitHandler:
    
    def __init__(self, repo_path: str) -> None:
        logger.info(f"Initializing GitHandler with repo_path: {repo_path}")
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)
        logger.debug(f"Repository initialized: {self.repo}")
    
    def get_recent_commits(self, n: int = 10) -> List[git.Commit]:
        logger.info(f"Getting recent {n} commits")
        commits = []
        try:
            for commit in self.repo.iter_commits(max_count=n):
                logger.debug(f"Processing commit: {commit.hexsha[:8]}")
                commits.append(commit)
            logger.info(f"Found {len(commits)} commits")
        except Exception as e:
            logger.error(f"Error getting recent commits: {e}")
            raise
        return commits
    
    def get_commits_range(self, start_commit: str, end_commit: Optional[str] = None) -> List[git.Commit]:
        logger.info(f"Getting commits range - start: {start_commit}, end: {end_commit}")
        commits = []
        try:
            if end_commit:
                
                
                rev_range = f"{start_commit}^..{end_commit}"
                logger.debug(f"Using inclusive range: {rev_range}")
                for commit in self.repo.iter_commits(rev_range):
                    logger.debug(f"Found commit in range: {commit.hexsha[:8]}")
                    commits.append(commit)
            else:
                
                rev_range = f"{start_commit}^..{start_commit}"
                logger.debug(f"Single commit range: {rev_range}")
                for commit in self.repo.iter_commits(rev_range):
                    logger.debug(f"Found single commit: {commit.hexsha[:8]}")
                    commits.append(commit)
            
            logger.info(f"Found {len(commits)} commits in range (inclusive)")
        except Exception as e:
            logger.error(f"Error getting commits range: {e}")
            logger.error(f"Start commit: {start_commit}, End commit: {end_commit}")
            raise
        
        return commits
    
    def get_commit_diff(self, commit_hash: str) -> Optional[git.DiffIndex]:
        logger.info(f"Getting diff for commit: {commit_hash}")
        try:
            commit = self.repo.commit(commit_hash)
            logger.debug(f"Commit object retrieved: {commit}")
            if commit.parents:
                logger.debug(f"Commit has {len(commit.parents)} parent(s)")
                diff = commit.diff(commit.parents[0])
                logger.debug(f"Diff created with parent")
                return diff
            logger.debug("Commit has no parents (initial commit)")
            return None
        except Exception as e:
            logger.error(f"Error getting commit diff: {e}")
            raise
    
    def get_commit_changes(self, commit: git.Commit) -> List[Dict[str, Any]]:
        logger.info(f"Getting changes for commit: {commit.hexsha[:8]}")
        changes = []
        
        try:
            if not commit.parents:
                logger.debug("Initial commit detected - no parents")
                parent = None
                diffs = commit.diff(None, create_patch=True)
            else:
                logger.debug(f"Commit has {len(commit.parents)} parent(s)")
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)
            
            logger.debug(f"Processing {len(diffs) if diffs else 0} diff items")
            
            for diff_item in diffs:
                file_path = diff_item.a_path or diff_item.b_path
                logger.debug(f"Processing diff for file: {file_path}")
                
                change = {
                    'file_path': file_path,
                    'change_type': diff_item.change_type,
                    'added_lines': [],
                    'removed_lines': []
                }
                
                if diff_item.diff:
                    diff_text = diff_item.diff.decode('utf-8', errors='ignore')
                    lines = diff_text.split('\n')
                    
                    for line in lines:
                        if line.startswith('+') and not line.startswith('+++'):
                            change['added_lines'].append(line[1:])
                        elif line.startswith('-') and not line.startswith('---'):
                            change['removed_lines'].append(line[1:])
                    
                    logger.debug(f"File {file_path}: {len(change['added_lines'])} added lines, {len(change['removed_lines'])} removed lines")
                
                changes.append(change)
            
            logger.info(f"Processed {len(changes)} file changes")
        except Exception as e:
            logger.error(f"Error getting commit changes: {e}")
            logger.error(f"Commit: {commit.hexsha if commit else 'None'}")
            raise
        
        return changes
