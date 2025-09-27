import argparse
import json
import os
from src.git_secret_scanner.git_handler import GitHandler

def main():
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default='.', help='Path to Git repository')
    parser.add_argument('--from', dest='from_commit', type=str, help='Start commit (hash or reference)')
    parser.add_argument('--to', dest='to_commit', type=str, help='End commit (hash or reference, optional)')
    parser.add_argument('--out', type=str, default='report.json', help='Output file')
    
    args = parser.parse_args()
    
    if not args.from_commit:
        print("Error: --from commit is required")
        return 1
    
    try:
        print(f"Scanning repository: {args.repo}")
        if args.to_commit:
            print(f"Analyzing commits from {args.from_commit} to {args.to_commit}...")
        else:
            print(f"Analyzing commit {args.from_commit}...")
        
        handler = GitHandler(args.repo)
        commits = handler.get_commits_range(args.from_commit, args.to_commit)
        
        findings = []
        suspicious_patterns = ['password', 'secret', 'api_key', 'token', 'private_key', 'access_key', 'auth', 'credential']
        
        for commit in commits:
            print(f"Checking commit {commit.hexsha[:8]}...")
            
            changes = handler.get_commit_changes(commit)
            
            for change in changes:
                file_path = change['file_path']
                
                if file_path.endswith('.json') and 'output' in file_path:
                    continue
                
                if file_path.endswith('_test.json') or file_path.endswith('_report.json'):
                    continue
                
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
