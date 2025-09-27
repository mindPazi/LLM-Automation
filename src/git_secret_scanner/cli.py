import argparse
import json
from src.git_secret_scanner.git_handler import GitHandler

def main():
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default='.', help='Path to Git repository')
    parser.add_argument('--n', type=int, default=10, help='Number of commits to scan')
    parser.add_argument('--out', type=str, default='report.json', help='Output file')
    
    args = parser.parse_args()
    
    try:
        print(f"Scanning repository: {args.repo}")
        print(f"Analyzing last {args.n} commits...")
        
        handler = GitHandler(args.repo)
        commits = handler.get_recent_commits(args.n)
        
        findings = []
        suspicious_patterns = ['password', 'secret', 'api_key', 'token', 'private_key', 'access_key', 'auth', 'credential']
        
        for commit in commits:
            print(f"Checking commit {commit.hexsha[:8]}...")
            
            for pattern in suspicious_patterns:
                if pattern.lower() in commit.message.lower():
                    finding = {
                        'commit_hash': commit.hexsha,
                        'author': str(commit.author),
                        'date': str(commit.committed_datetime),
                        'message': commit.message.strip(),
                        'finding_type': 'suspicious_keyword_in_message',
                        'pattern': pattern,
                        'confidence': 0.3
                    }
                    findings.append(finding)
            
            changes = handler.get_commit_changes(commit)
            
            for change in changes:
                file_path = change['file_path']
                
                for line_num, line in enumerate(change['added_lines'], 1):
                    for pattern in suspicious_patterns:
                        if pattern.lower() in line.lower():
                            finding = {
                                'commit_hash': commit.hexsha,
                                'author': str(commit.author),
                                'date': str(commit.committed_datetime),
                                'file_path': file_path,
                                'line_number': line_num,
                                'snippet': line[:200],
                                'finding_type': 'suspicious_keyword_in_diff',
                                'pattern': pattern,
                                'confidence': 0.5
                            }
                            findings.append(finding)
        
        with open(args.out, 'w') as f:
            json.dump({
                'repository': args.repo,
                'commits_scanned': len(commits),
                'findings': findings
            }, f, indent=2)
        
        print(f"\nReport saved to: {args.out}")
        print(f"Found {len(findings)} potential issues")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
