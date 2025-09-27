class GitSecretScanner:
    
    def __init__(self, repo_path, model_name="gpt-3.5-turbo", use_heuristics=True):
        self.repo_path = repo_path
        self.model_name = model_name
        self.use_heuristics = use_heuristics
    
    def scan(self, commits_count=10, output_path="report.json"):
        pass
