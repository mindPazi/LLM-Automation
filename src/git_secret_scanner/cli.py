import argparse
import os
from typing import List, Dict, Any, Optional
import git
from dotenv import load_dotenv
from src.git_secret_scanner.git_handler import GitHandler
from src.git_secret_scanner.llm_analyzer import LLMAnalyzer
from src.git_secret_scanner.heuristics import HeuristicFilter
from src.git_secret_scanner.report import ReportGenerator
from src.git_secret_scanner.logger_config import setup_logger

load_dotenv()

def main() -> int:
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default='.', help='Path to Git repository')
    parser.add_argument('--from', dest='from_commit', type=str, help='Start commit (hash or reference)')
    parser.add_argument('--to', dest='to_commit', type=str, help='End commit (hash or reference, optional)')
    parser.add_argument('--last', type=int, help='Scan last n commits (alternative to --from/--to)')
    parser.add_argument('--out', type=str, default='report.json', help='Output file')
    parser.add_argument('--mode', type=str, choices=['llm-only', 'heuristic-only', 'llm-fallback', 'llm-validated'], 
                       default='llm-fallback', help='Scan mode: llm-only, heuristic-only, llm-fallback, or llm-validated (uses heuristics to filter LLM false positives)')
    parser.add_argument('--model', type=str, default='gpt-5-mini', help='Model name (default: gpt-5-mini)')
    parser.add_argument('--log-level', type=str, default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set the logging level (default: INFO)')
    parser.add_argument('--log-file', type=str, help='Log file path (optional)')
    
    args = parser.parse_args()
    
    global logger
    logger = setup_logger(level=args.log_level, log_file=args.log_file)
    
    if not args.last and not args.from_commit:
        logger.error("Either --last n or --from commit is required")
        return 1
    
    if args.last and args.from_commit:
        logger.error("Cannot use both --last and --from/--to options together")
        return 1
    
    try:
        logger.info(f"Scanning repository: {args.repo}")
        logger.info(f"Mode: {args.mode}")
        
        
        handler = GitHandler(args.repo)
        
        if args.last:
            logger.info(f"Analyzing last {args.last} commits...")
            commits = handler.get_recent_commits(args.last)
        else:
            if args.to_commit:
                logger.info(f"Analyzing commits from {args.from_commit} to {args.to_commit}...")
            else:
                logger.info(f"Analyzing commit {args.from_commit}...")
            commits = handler.get_commits_range(args.from_commit, args.to_commit)
        
        llm_analyzer = None
        if args.mode in ['llm-only', 'llm-fallback', 'llm-validated']:
            logger.info(f"Initializing {args.model} model...")
            llm_analyzer = LLMAnalyzer(model_name=args.model)
            llm_analyzer.load_model()
            logger.info(f"Model {args.model} loaded successfully")
        
        heuristic_filter = HeuristicFilter()
        report_generator = ReportGenerator()
        
        for commit in commits:
            logger.debug(f"Checking commit {commit.hexsha[:8]}...")
            
            changes = handler.get_commit_changes(commit)
            
            for change in changes:
                file_path = change['file_path']
                
                if file_path.endswith('.json') and 'output' in file_path:
                    continue
                
                if file_path.endswith('_test.json') or file_path.endswith('_report.json'):
                    continue
                
                if file_path.lower() in ['readme.md', 'readme.txt', 'readme.rst', 'readme']:
                    continue
                
                
                if len(change['added_lines']) == 0:
                    continue
                
                if args.mode == 'llm-only' and llm_analyzer:
                    process_llm_only(llm_analyzer, change['added_lines'], commit, file_path, 
                                   report_generator, args.model)
                
                elif args.mode == 'heuristic-only':
                    process_heuristic_only(heuristic_filter, change['added_lines'], commit, 
                                         file_path, report_generator)
                
                elif args.mode == 'llm-validated' and llm_analyzer:
                    process_llm_validated(llm_analyzer, heuristic_filter, change['added_lines'], 
                                        commit, file_path, report_generator, args.model)
                
                elif args.mode == 'llm-fallback':
                    process_llm_fallback(llm_analyzer, heuristic_filter, change['added_lines'], 
                                       commit, file_path, report_generator, args.model)
        
        report_generator.save_current_report(args.repo, args.mode, len(commits), args.out)
        
        logger.info(f"Report saved to: {args.out}")
        logger.info(f"Found {len(report_generator.get_findings())} potential issues")
        
        report_generator.print_current_summary(args.mode)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    
    return 0

def analyze_with_llm(llm_analyzer: LLMAnalyzer, added_lines: List[str]) -> List[Dict[str, Any]]:
    diff_content = '\n'.join(added_lines)
    llm_result = llm_analyzer.analyze_diff(diff_content)
    return llm_analyzer.extract_findings(llm_result)

def process_llm_only(llm_analyzer: LLMAnalyzer, added_lines: List[str], commit: git.Commit, 
                     file_path: str, report_generator: ReportGenerator, model_name: str) -> None:
    llm_secrets = analyze_with_llm(llm_analyzer, added_lines)
    
    if llm_secrets:
        logger.info(f"LLM found {len(llm_secrets)} secret(s) in {file_path}")
    
    for secret in llm_secrets:
        report_generator.add_llm_finding(commit, file_path, secret, model_name)

def process_heuristic_only(heuristic_filter: HeuristicFilter, added_lines: List[str], 
                          commit: git.Commit, file_path: str, report_generator: ReportGenerator) -> None:
    heuristic_results = heuristic_filter.apply_regex_filters(added_lines)
    
    if heuristic_results:
        logger.info(f"Heuristic found {len(heuristic_results)} secret(s) in {file_path}")
    
    for heuristic_finding in heuristic_results:
        report_generator.add_heuristic_finding(commit, file_path, heuristic_finding)

def process_llm_validated(llm_analyzer: LLMAnalyzer, heuristic_filter: HeuristicFilter, 
                         added_lines: List[str], commit: git.Commit, file_path: str, 
                         report_generator: ReportGenerator, model_name: str) -> None:
    llm_secrets = analyze_with_llm(llm_analyzer, added_lines)
    
    if not llm_secrets:
        return
    
    unique_secrets = []
    for secret in llm_secrets:
        unique_id = f"{commit.hexsha}:{file_path}:{secret['value']}"
        
        if unique_id not in report_generator.seen_secrets:
            unique_secrets.append(secret)
    
    validated_secrets = []
    false_positives = []
    
    for secret in unique_secrets:
        initial_confidence = heuristic_filter.calculate_confidence(
            secret['key'], 
            secret['value'], 
            secret.get('type')
        )
        
        adjusted_confidence, should_filter = heuristic_filter.adjust_confidence_with_heuristics(
            initial_confidence, 
            secret['key'], 
            secret['value']
        )
        
        secret['adjusted_confidence'] = round(adjusted_confidence, 2)
        
        if should_filter:
            secret['filtered_reason'] = f'Confidence too low: {adjusted_confidence:.2f} < 0.5'
            false_positives.append(secret)
        else:
            validated_secrets.append(secret)
    
    actually_added = 0
    for secret in validated_secrets:
        result = report_generator.add_validated_llm_finding(commit, file_path, secret, model_name)
        if result is not None:
            actually_added += 1
    
    false_positives_added = 0
    for secret in false_positives:
        result = report_generator.add_llm_false_positive(commit, file_path, secret, model_name)
        if result is not None:
            false_positives_added += 1
    
    if actually_added > 0 or false_positives_added > 0:
        total_unique = actually_added + false_positives_added
        logger.info(f"LLM found {total_unique} secret(s) → {actually_added} validated (confidence ≥ 0.5), {false_positives_added} filtered (confidence < 0.5) in {file_path}")
    elif len(unique_secrets) > 0:
        logger.info(f"LLM found {len(unique_secrets)} secret(s) → all filtered as low confidence in {file_path}")

def process_llm_fallback(llm_analyzer: Optional[LLMAnalyzer], heuristic_filter: HeuristicFilter, 
                        added_lines: List[str], commit: git.Commit, file_path: str, 
                        report_generator: ReportGenerator, model_name: str) -> None:
    llm_found_secrets = False
    
    if llm_analyzer:
        llm_secrets = analyze_with_llm(llm_analyzer, added_lines)
        
        if llm_secrets:
            llm_found_secrets = True
            logger.info(f"LLM found {len(llm_secrets)} secret(s) in {file_path}")
            
            for secret in llm_secrets:
                report_generator.add_llm_finding(commit, file_path, secret, model_name)
    
    if not llm_found_secrets:
        heuristic_results = heuristic_filter.apply_regex_filters(added_lines)
        
        if heuristic_results:
            logger.info(f"Heuristic found {len(heuristic_results)} secret(s) missed by LLM in {file_path}")
            
            for heuristic_finding in heuristic_results:
                report_generator.add_heuristic_finding(commit, file_path, heuristic_finding, 
                                                      'heuristic_fallback_secret')

if __name__ == "__main__":
    main()
