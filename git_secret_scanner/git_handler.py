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
    
    def get_commit_diff(self, commit_hash):
        commit = self.repo.commit(commit_hash)
        if commit.parents:
            diff = commit.diff(commit.parents[0])
            return diff
        return None
