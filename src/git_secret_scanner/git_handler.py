import git

class GitHandler:
    
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)
    
    def get_recent_commits(self, n=10):
        commits = []
        for commit in self.repo.iter_commits(max_count=n):
            commits.append(commit)
        return commits
    
    def get_commits_range(self, start_commit, end_commit=None):
        commits = []
        if end_commit:
            rev_range = f"{start_commit}..{end_commit}"
            for commit in self.repo.iter_commits(rev_range):
                commits.append(commit)
        else:
            rev_range = f"{start_commit}^..{start_commit}"
            for commit in self.repo.iter_commits(rev_range):
                commits.append(commit)
        
        return commits
    
    def get_commit_diff(self, commit_hash):
        commit = self.repo.commit(commit_hash)
        if commit.parents:
            diff = commit.diff(commit.parents[0])
            return diff
        return None
    
    def get_commit_changes(self, commit):
        changes = []
        
        if not commit.parents:
            parent = None
            diffs = commit.diff(None, create_patch=True)
        else:
            parent = commit.parents[0]
            diffs = parent.diff(commit, create_patch=True)
        
        for diff_item in diffs:
            change = {
                'file_path': diff_item.a_path or diff_item.b_path,
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
            
            changes.append(change)
        
        return changes
