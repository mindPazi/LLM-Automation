import argparse
import json
import os
from dotenv import load_dotenv
from src.git_secret_scanner.git_handler import GitHandler
from src.git_secret_scanner.llm_analyzer import LLMAnalyzer
from src.git_secret_scanner.heuristics import HeuristicFilter

load_dotenv()

def main():
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default='.', help='Path to Git repository')
    parser.add_argument('--from', dest='from_commit', type=str, help='Start commit (hash or reference)')
    parser.add_argument('--to', dest='to_commit', type=str, help='End commit (hash or reference, optional)')
    parser.add_argument('--out', type=str, default='report.json', help='Output file')
    parser.add_argument('--use-llm', action='store_true', help='Use gpt-5-nano model for analysis')
    parser.add_argument('--model', type=str, default='gpt-5-nano', help='Model name (default: gpt-5-nano)')
    parser.add_argument('--llm-only', action='store_true', help='Use only LLM without heuristic fallback')
    
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
        
        llm_analyzer = None
        if args.use_llm:
            print(f"Initializing {args.model} model...")
            llm_analyzer = LLMAnalyzer(model_name=args.model)
            llm_analyzer.load_model()
            print(f"Model {args.model} loaded successfully")
        
        handler = GitHandler(args.repo)
        commits = handler.get_commits_range(args.from_commit, args.to_commit)
        
        heuristic_filter = HeuristicFilter()
        
        findings = []
        llm_secrets_count = 0
        heuristic_only_secrets_count = 0
        
        for commit in commits:
            print(f"Checking commit {commit.hexsha[:8]}...")
            
            changes = handler.get_commit_changes(commit)
            
            for change in changes:
                file_path = change['file_path']
                
                if file_path.endswith('.json') and 'output' in file_path:
                    continue
                
                if file_path.endswith('_test.json') or file_path.endswith('_report.json'):
                    continue
                
                if file_path.lower() in ['readme.md', 'readme.txt', 'readme.rst', 'readme']:
                    continue
                
                llm_findings_found = False
                llm_secrets_in_file = 0
                
                if llm_analyzer and len(change['added_lines']) > 0:
                    diff_content = '\n'.join(change['added_lines'])
                    llm_result = llm_analyzer.analyze_diff(diff_content)
                    
                    if args.llm_only:
                        print(f"  └─ LLM response for {file_path}:")
                        print(f"      {llm_result}")
                    
                    llm_secrets = llm_analyzer.extract_findings(llm_result)
                    
                    if llm_secrets:
                        llm_secrets_in_file = len(llm_secrets)
                        llm_secrets_count += llm_secrets_in_file
                        print(f"  └─ LLM found {llm_secrets_in_file} secret(s) in {file_path}")
                    
                    for secret in llm_secrets:
                        llm_findings_found = True
                        finding = {
                            'commit_hash': commit.hexsha,
                            'author': str(commit.author),
                            'date': str(commit.committed_datetime),
                            'file_path': file_path,
                            'finding_type': 'llm_detected_secret',
                            'model': args.model,
                            'secret_key': secret['key'],
                            'secret_value': secret['value'],
                            'confidence': 0.9
                        }
                        findings.append(finding)
                
                heuristic_secrets_in_file = 0
                if not llm_findings_found and not args.llm_only:
                    heuristic_findings = heuristic_filter.apply_regex_filters(change['added_lines'])
                    
                    for heuristic_finding in heuristic_findings:
                        finding = {
                            'commit_hash': commit.hexsha,
                            'author': str(commit.author),
                            'date': str(commit.committed_datetime),
                            'file_path': file_path,
                            'line_number': heuristic_finding['line_number'],
                            'snippet': heuristic_finding['line'],
                            'finding_type': 'heuristic_detected_secret',
                            'pattern': heuristic_finding['pattern_type'],
                            'secret_key': heuristic_finding['secret_key'],
                            'secret_value': heuristic_finding['secret_value'],
                            'entropy': heuristic_finding['entropy'],
                            'confidence': 0.7
                        }
                        findings.append(finding)
                        heuristic_secrets_in_file += 1
                
                if heuristic_secrets_in_file > 0 and not llm_findings_found:
                    heuristic_only_secrets_count += heuristic_secrets_in_file
                    if llm_analyzer:
                        print(f"  └─ Heuristic found {heuristic_secrets_in_file} secret(s) missed by LLM in {file_path}")
        
        with open(args.out, 'w') as f:
            json.dump({
                'repository': args.repo,
                'commits_scanned': len(commits),
                'findings': findings
            }, f, indent=2)
        
        print(f"\nReport saved to: {args.out}")
        print(f"Found {len(findings)} potential issues")
        
        if llm_analyzer:
            print(f"\n📊 Analysis Summary:")
            print(f"  - LLM detected: {llm_secrets_count} secret(s)")
            print(f"  - Heuristic fallback detected: {heuristic_only_secrets_count} additional secret(s)")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
