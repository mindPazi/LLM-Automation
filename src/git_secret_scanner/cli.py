import argparse
import sys
from dotenv import load_dotenv
from src.git_secret_scanner.git_handler import GitHandler
from src.git_secret_scanner.llm_analyzer import LLMAnalyzer
from src.git_secret_scanner.heuristics import HeuristicFilter
from src.git_secret_scanner.report import ReportGenerator
from src.git_secret_scanner.logger_config import setup_logger
from src.git_secret_scanner.config_loader import config

load_dotenv()

def main() -> int:
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets')
    parser.add_argument('--repo', type=str, default=config.get('cli', 'default_repo', default='.'), help='Path to Git repository')
    parser.add_argument('--from', dest='from_commit', type=str, help='Start commit (hash or reference)')
    parser.add_argument('--to', dest='to_commit', type=str, help='End commit (hash or reference, optional)')
    parser.add_argument('--last', type=int, help='Scan last n commits (alternative to --from/--to)')
    parser.add_argument('--out', type=str, default=config.get('cli', 'default_output', default='report.json'), help='Output file')
    parser.add_argument('--mode', type=str, choices=['llm-only', 'heuristic-only', 'llm-fallback', 'llm-validated'], 
                       default=config.get('cli', 'default_mode', default='llm-fallback'), help='Scan mode: llm-only, heuristic-only, llm-fallback, or llm-validated (uses heuristics to filter LLM false positives)')
    parser.add_argument('--model', type=str, default=config.get('llm', 'default_model', default='gpt-5'), help='Model name')
    parser.add_argument('--log-level', type=str, default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set the logging level (default: INFO)')
    parser.add_argument('--log-file', type=str, help='Log file path (optional)')
    
    args = parser.parse_args()
    
    global logger
    logger = setup_logger(level=args.log_level, log_file=args.log_file)
    logger.debug(f"Arguments parsed: {args}")
    
    if not args.last and not args.from_commit:
        logger.error("Either --last n or --from commit is required")
        return 1
    
    if args.last and args.from_commit:
        logger.error("Cannot use both --last and --from/--to options together")
        return 1
    
    try:
        logger.info(f"Scanning repository: {args.repo}")
        logger.info(f"Mode: {args.mode}")
        
        logger.debug("Creating GitHandler")
        handler = GitHandler(args.repo)
        logger.debug("GitHandler created successfully")
        
        if args.last:
            logger.info(f"Analyzing last {args.last} commits...")
            commits = handler.get_recent_commits(args.last)
            logger.debug(f"Retrieved {len(commits) if commits else 0} commits")
        else:
            if args.to_commit:
                logger.info(f"Analyzing commits from {args.from_commit} to {args.to_commit}...")
            else:
                logger.info(f"Analyzing commit {args.from_commit}...")
            commits = handler.get_commits_range(args.from_commit, args.to_commit)
            logger.debug(f"Retrieved {len(commits) if commits else 0} commits from range")
        
        llm_analyzer = None
        if args.mode in ['llm-only', 'llm-fallback', 'llm-validated']:
            logger.info(f"Initializing {args.model} model...")
            llm_analyzer = LLMAnalyzer(model_name=args.model)
            llm_analyzer.load_model()
            logger.info(f"Model {args.model} loaded successfully")
        else:
            logger.debug(f"LLM not needed for mode: {args.mode}")
        
        logger.debug("Creating HeuristicFilter")
        heuristic_filter = HeuristicFilter()
        logger.debug("HeuristicFilter created")
        
        logger.debug("Creating ReportGenerator")
        report_generator = ReportGenerator()
        logger.debug("ReportGenerator created")
        
        logger.info(f"Processing {len(commits)} commits")
        for i, commit in enumerate(commits):
            logger.info(f"Processing commit {i+1}/{len(commits)}: {commit.hexsha[:8]}")
            
            commit_msg_lines = commit.message.strip().split('\n')
            if commit_msg_lines:
                logger.debug(f"Processing commit message ({len(commit_msg_lines)} lines)")
                try:
                    if args.mode == 'llm-only' and llm_analyzer:
                        llm_analyzer.process_llm_only(commit_msg_lines, commit, "COMMIT_MESSAGE", 
                                                      report_generator, args.model)
                    elif args.mode == 'heuristic-only':
                        heuristic_filter.process_heuristic_only(commit_msg_lines, commit, 
                                                                "COMMIT_MESSAGE", report_generator)
                    elif args.mode == 'llm-validated' and llm_analyzer:
                        llm_analyzer.process_llm_validated(heuristic_filter, commit_msg_lines, 
                                                           commit, "COMMIT_MESSAGE", report_generator, args.model)
                    elif args.mode == 'llm-fallback':
                        llm_analyzer.process_llm_fallback(heuristic_filter, commit_msg_lines, 
                                                          commit, "COMMIT_MESSAGE", report_generator, args.model)
                except Exception as e:
                    logger.error(f"Error processing commit message: {e}")
            
            try:
                changes = handler.get_commit_changes(commit)
                logger.debug(f"Commit has {len(changes)} file changes")
            except Exception as e:
                logger.error(f"Error getting changes for commit {commit.hexsha[:8]}: {e}")
                continue
            
            if not changes:
                logger.info(f"No file changes in commit {commit.hexsha[:8]}")
                continue
            
            files_processed = 0
            secrets_found_in_commit = 0
            
            for change in changes:
                file_path = change['file_path']
                logger.debug(f"Processing file: {file_path}")
                
                if file_path.endswith('.json') and 'output' in file_path:
                    logger.debug(f"Skipping output file: {file_path}")
                    continue
                
                if file_path.endswith('_test.json') or file_path.endswith('_report.json'):
                    logger.debug(f"Skipping test/report file: {file_path}")
                    continue
                
                if file_path.lower() in ['readme.md', 'readme.txt', 'readme.rst', 'readme']:
                    logger.debug(f"Skipping readme file: {file_path}")
                    continue
                
                if file_path.lower() == 'config.yaml' or file_path.endswith('/config.yaml'):
                    logger.debug(f"Skipping config.yaml file: {file_path}")
                    continue
                
                
                if 'tests/unit/' in file_path or file_path.startswith('unit/'):
                    logger.debug(f"Skipping unit test file: {file_path}")
                    continue
                
                if len(change['added_lines']) == 0:
                    logger.debug(f"No added lines in file: {file_path}")
                    continue
                
                files_processed += 1
                
                logger.debug(f"Processing {len(change['added_lines'])} added lines in {file_path}")
                
                try:
                    found_secrets = 0
                    if args.mode == 'llm-only' and llm_analyzer:
                        logger.debug("Processing with LLM-only mode")
                        found_secrets = llm_analyzer.process_llm_only(change['added_lines'], commit, file_path, 
                                       report_generator, args.model)
                    
                    elif args.mode == 'heuristic-only':
                        logger.debug("Processing with heuristic-only mode")
                        found_secrets = heuristic_filter.process_heuristic_only(change['added_lines'], commit, 
                                             file_path, report_generator)
                    
                    elif args.mode == 'llm-validated' and llm_analyzer:
                        logger.debug("Processing with LLM-validated mode")
                        found_secrets = llm_analyzer.process_llm_validated(heuristic_filter, change['added_lines'], 
                                            commit, file_path, report_generator, args.model)
                    
                    elif args.mode == 'llm-fallback':
                        logger.debug("Processing with LLM-fallback mode")
                        found_secrets = llm_analyzer.process_llm_fallback(heuristic_filter, change['added_lines'], 
                                           commit, file_path, report_generator, args.model)
                    
                    secrets_found_in_commit += found_secrets
                except Exception as e:
                    logger.error(f"Error processing file {file_path} in mode {args.mode}: {e}")
                    logger.debug(f"Error details:", exc_info=True)
            
            if files_processed == 0:
                logger.info(f"No processable files with changes in commit {commit.hexsha[:8]}")
            elif secrets_found_in_commit == 0:
                logger.info(f"No secrets found in commit {commit.hexsha[:8]} ({files_processed} files processed)")
            else:
                logger.info(f"Found {secrets_found_in_commit} potential secrets in commit {commit.hexsha[:8]} ({files_processed} files processed)")
        
        logger.debug("Saving report")
        report_generator.save_current_report(args.repo, args.mode, len(commits), args.out)
        
        logger.info(f"Report saved to: {args.out}")
        
        total_findings = len(report_generator.get_findings())
        if report_generator.duplicates_count > 0:
            logger.info(f"Found {total_findings} unique potential issues ({report_generator.duplicates_count} duplicates removed)")
        else:
            logger.info(f"Found {total_findings} unique potential issues")
        
        logger.debug("Printing summary")
        report_generator.print_current_summary(args.mode)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.debug("Full error details:", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
