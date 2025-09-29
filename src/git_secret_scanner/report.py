import json

class ReportGenerator:
    
    def __init__(self):
        self.findings = []
        self.filtered_false_positives = []
    
    def add_llm_finding(self, commit, file_path, secret, model_name):
        finding = self.create_llm_finding(commit, file_path, secret, model_name)
        self.findings.append(finding)
        return finding
    
    def add_validated_llm_finding(self, commit, file_path, secret, model_name):
        finding = self.create_llm_finding(commit, file_path, secret, model_name)
        finding['finding_type'] = 'llm_validated_secret'
        self.findings.append(finding)
        return finding
    
    def add_llm_false_positive(self, commit, file_path, secret, model_name):
        false_positive = self.create_llm_finding(commit, file_path, secret, model_name)
        false_positive['finding_type'] = 'llm_false_positive'
        false_positive['filtered_reason'] = 'Failed heuristic validation'
        self.filtered_false_positives.append(false_positive)
        return false_positive
    
    def add_heuristic_finding(self, commit, file_path, heuristic_finding, finding_type='heuristic_detected_secret'):
        finding = self.create_heuristic_finding(commit, file_path, heuristic_finding, finding_type)
        self.findings.append(finding)
        return finding
    
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
    
    def get_findings(self):
        return self.findings
    
    def get_false_positives(self):
        return self.filtered_false_positives
    
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
    
    def save_report_with_false_positives(self, repository, scan_mode, commits_count, findings, false_positives, output_path):
        report = {
            'repository': repository,
            'scan_mode': scan_mode,
            'commits_scanned': commits_count,
            'findings': findings,
            'filtered_false_positives': false_positives
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def save_current_report(self, repository, scan_mode, commits_count, output_path):
        if self.filtered_false_positives:
            return self.save_report_with_false_positives(
                repository, scan_mode, commits_count, 
                self.findings, self.filtered_false_positives, output_path
            )
        else:
            return self.save_report(
                repository, scan_mode, commits_count, 
                self.findings, output_path
            )
    
    def print_summary(self, findings, scan_mode):
        llm_secrets_count = sum(1 for f in findings if 'llm_detected' in f.get('finding_type', ''))
        heuristic_secrets_count = sum(1 for f in findings if f.get('finding_type', '') == 'heuristic_detected_secret')
        heuristic_fallback_count = sum(1 for f in findings if 'heuristic_fallback' in f.get('finding_type', ''))
        llm_validated_count = sum(1 for f in findings if 'llm_validated' in f.get('finding_type', ''))
        
        print(f"\n📊 Analysis Summary:")
        if scan_mode == 'llm-only':
            print(f"  - LLM detected: {llm_secrets_count} secret(s)")
        elif scan_mode == 'heuristic-only':
            print(f"  - Heuristic detected: {heuristic_secrets_count} secret(s)")
        elif scan_mode == 'llm-fallback':
            print(f"  - LLM detected: {llm_secrets_count} secret(s)")
            print(f"  - Heuristic fallback detected: {heuristic_fallback_count} additional secret(s)")
        elif scan_mode == 'llm-validated':
            print(f"  - LLM validated secrets: {llm_validated_count} secret(s)")
            print(f"  - False positives filtered by heuristics")
    
    def print_current_summary(self, scan_mode):
        self.print_summary(self.findings, scan_mode)
