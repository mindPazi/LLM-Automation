import argparse
import os
from dotenv import load_dotenv
from src.git_secret_scanner.git_handler import GitHandler
from src.git_secret_scanner.llm_analyzer import LLMAnalyzer
from src.git_secret_scanner.heuristics import HeuristicFilter
from src.git_secret_scanner.report import ReportGenerator

load_dotenv()

def main():
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default='.', help='Path to Git repository')
    parser.add_argument('--from', dest='from_commit', type=str, help='Start commit (hash or reference)')
    parser.add_argument('--to', dest='to_commit', type=str, help='End commit (hash or reference, optional)')
    parser.add_argument('--out', type=str, default='report.json', help='Output file')
    parser.add_argument('--mode', type=str, choices=['llm-only', 'heuristic-only', 'llm-fallback', 'llm-validated'], 
                       default='llm-fallback', help='Scan mode: llm-only, heuristic-only, llm-fallback, or llm-validated (uses heuristics to filter LLM false positives)')
    parser.add_argument('--model', type=str, default='gpt-5-mini', help='Model name (default: gpt-5-mini)')
    
    args = parser.parse_args()
    
    if not args.from_commit:
        print("Error: --from commit is required")
        return 1
    
    try:
        print(f"Scanning repository: {args.repo}")
        print(f"Mode: {args.mode}")
        if args.to_commit:
            print(f"Analyzing commits from {args.from_commit} to {args.to_commit}...")
        else:
            print(f"Analyzing commit {args.from_commit}...")
        
        llm_analyzer = None
        if args.mode in ['llm-only', 'llm-fallback', 'llm-validated']:
            print(f"Initializing {args.model} model...")
            llm_analyzer = LLMAnalyzer(model_name=args.model)
            llm_analyzer.load_model()
            print(f"Model {args.model} loaded successfully")
        
        handler = GitHandler(args.repo)
        commits = handler.get_commits_range(args.from_commit, args.to_commit)
        
        heuristic_filter = HeuristicFilter()
        report_generator = ReportGenerator()
        
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
                
                
                if args.mode == 'llm-only' and llm_analyzer and len(change['added_lines']) > 0:
                    diff_content = '\n'.join(change['added_lines'])
                    llm_result = llm_analyzer.analyze_diff(diff_content)
                    
                    llm_secrets = llm_analyzer.extract_findings(llm_result)
                    
                    if llm_secrets:
                        print(f"  └─ LLM found {len(llm_secrets)} secret(s) in {file_path}")
                    
                    for secret in llm_secrets:
                        report_generator.add_llm_finding(commit, file_path, secret, args.model)
                
                elif args.mode == 'heuristic-only':
                    heuristic_results = heuristic_filter.apply_regex_filters(change['added_lines'])
                    
                    if heuristic_results:
                        print(f"  └─ Heuristic found {len(heuristic_results)} secret(s) in {file_path}")
                    
                    for heuristic_finding in heuristic_results:
                        report_generator.add_heuristic_finding(commit, file_path, heuristic_finding)
                
                elif args.mode == 'llm-validated' and llm_analyzer and len(change['added_lines']) > 0:
                    diff_content = '\n'.join(change['added_lines'])
                    llm_result = llm_analyzer.analyze_diff(diff_content)
                    llm_secrets = llm_analyzer.extract_findings(llm_result)
                    
                    validated_secrets = []
                    false_positives_count = 0
                    
                    for secret in llm_secrets:
                        if heuristic_filter.validate_llm_finding(secret['key'], secret['value']):
                            validated_secrets.append(secret)
                        else:
                            false_positives_count += 1
                            report_generator.add_llm_false_positive(commit, file_path, secret, args.model)
                    
                    if validated_secrets:
                        print(f"  └─ LLM found {len(llm_secrets)} secret(s), {len(validated_secrets)} validated, {false_positives_count} false positives filtered in {file_path}")
                        
                        for secret in validated_secrets:
                            report_generator.add_validated_llm_finding(commit, file_path, secret, args.model)
                    elif llm_secrets:
                        print(f"  └─ LLM found {len(llm_secrets)} secret(s), all filtered as false positives in {file_path}")
                
                elif args.mode == 'llm-fallback' and len(change['added_lines']) > 0:
                    llm_found_secrets = False
                    
                    if llm_analyzer:
                        diff_content = '\n'.join(change['added_lines'])
                        llm_result = llm_analyzer.analyze_diff(diff_content)
                        llm_secrets = llm_analyzer.extract_findings(llm_result)
                        
                        if llm_secrets:
                            llm_found_secrets = True
                            print(f"  └─ LLM found {len(llm_secrets)} secret(s) in {file_path}")
                            
                            for secret in llm_secrets:
                                report_generator.add_llm_finding(commit, file_path, secret, args.model)
                    
                    if not llm_found_secrets:
                        heuristic_results = heuristic_filter.apply_regex_filters(change['added_lines'])
                        
                        if heuristic_results:
                            print(f"  └─ Heuristic found {len(heuristic_results)} secret(s) missed by LLM in {file_path}")
                            
                            for heuristic_finding in heuristic_results:
                                report_generator.add_heuristic_finding(commit, file_path, heuristic_finding, 'heuristic_fallback_secret')
        
        report_generator.save_current_report(args.repo, args.mode, len(commits), args.out)
        
        print(f"\nReport saved to: {args.out}")
        print(f"Found {len(report_generator.get_findings())} potential issues")
        
        report_generator.print_current_summary(args.mode)
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
