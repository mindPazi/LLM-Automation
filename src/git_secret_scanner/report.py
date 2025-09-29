import json

class ReportGenerator:
    
    def __init__(self):
        pass
    
    def create_llm_finding(self, commit, file_path, secret, model_name):
        return {
            'commit_hash': commit.hexsha,
            'author': str(commit.author),
            'date': str(commit.committed_datetime),
            'file_path': file_path,
            'finding_type': 'llm_detected_secret',
            'model': model_name,
            'secret_key': secret['key'],
            'secret_value': secret['value'],
            'confidence': 0.9
        }
    
    def create_heuristic_finding(self, commit, file_path, heuristic_finding, finding_type='heuristic_detected_secret'):
        return {
            'commit_hash': commit.hexsha,
            'author': str(commit.author),
            'date': str(commit.committed_datetime),
            'file_path': file_path,
            'line_number': heuristic_finding['line_number'],
            'snippet': heuristic_finding['line'],
            'finding_type': finding_type,
            'pattern': heuristic_finding['pattern_type'],
            'secret_key': heuristic_finding['secret_key'],
            'secret_value': heuristic_finding['secret_value'],
            'entropy': heuristic_finding['entropy'],
            'confidence': 0.7
        }
    
    def save_report(self, repository, scan_mode, commits_count, findings, output_path):
        report = {
            'repository': repository,
            'scan_mode': scan_mode,
            'commits_scanned': commits_count,
            'findings': findings
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def print_summary(self, findings, scan_mode):
        llm_secrets_count = sum(1 for f in findings if 'llm_detected' in f.get('finding_type', ''))
        heuristic_secrets_count = sum(1 for f in findings if 'heuristic' in f.get('finding_type', ''))
        heuristic_fallback_count = sum(1 for f in findings if 'heuristic_fallback' in f.get('finding_type', ''))
        
        print(f"\n📊 Analysis Summary:")
        if scan_mode == 'llm-only':
            print(f"  - LLM detected: {llm_secrets_count} secret(s)")
        elif scan_mode == 'heuristic-only':
            print(f"  - Heuristic detected: {heuristic_secrets_count} secret(s)")
        elif scan_mode == 'llm-fallback':
            print(f"  - LLM detected: {llm_secrets_count} secret(s)")
            print(f"  - Heuristic fallback detected: {heuristic_fallback_count} additional secret(s)")
