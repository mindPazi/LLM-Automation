import json
from typing import List, Dict, Any, Optional, Set
import git
from src.git_secret_scanner.heuristics import HeuristicFilter
from src.git_secret_scanner.logger_config import get_logger

logger = get_logger()

class ReportGenerator:
    
    def __init__(self) -> None:
        self.findings = []
        self.filtered_false_positives = []
        self.seen_secrets = set()
        self.seen_false_positives = set()
        self.heuristic_filter = HeuristicFilter()
        self.duplicates_count = 0
        self.llm_duplicates_count = 0
        self.heuristic_duplicates_count = 0
    
    def add_llm_finding(self, commit: git.Commit, file_path: str, secret: Dict[str, Any], model_name: str) -> Optional[Dict[str, Any]]:
        unique_id = f"{commit.hexsha}:{file_path}:{secret['value']}"
        
        if unique_id in self.seen_secrets:
            self.llm_duplicates_count += 1
            self.duplicates_count += 1
            return None
            
        self.seen_secrets.add(unique_id)
        finding = self.create_llm_finding(commit, file_path, secret, model_name)
        self.findings.append(finding)
        return finding
    
    def add_validated_llm_finding(self, commit: git.Commit, file_path: str, secret: Dict[str, Any], model_name: str) -> Optional[Dict[str, Any]]:
        unique_id = f"{commit.hexsha}:{file_path}:{secret['value']}"
        
        if unique_id in self.seen_secrets:
            self.llm_duplicates_count += 1
            self.duplicates_count += 1
            return None
            
        self.seen_secrets.add(unique_id)
        finding = self.create_llm_finding(commit, file_path, secret, model_name)
        finding['finding_type'] = 'llm_validated_secret'
        self.findings.append(finding)
        return finding
    
    def add_llm_false_positive(self, commit: git.Commit, file_path: str, secret: Dict[str, Any], model_name: str) -> Optional[Dict[str, Any]]:
        unique_id = f"{commit.hexsha}:{file_path}:{secret['value']}"
        
        if unique_id in self.seen_false_positives:
            return None
            
        self.seen_false_positives.add(unique_id)
        false_positive = self.create_llm_finding(commit, file_path, secret, model_name)
        false_positive['finding_type'] = 'llm_false_positive'
        false_positive['filtered_reason'] = 'Failed heuristic validation'
        self.filtered_false_positives.append(false_positive)
        return false_positive
    
    def add_heuristic_finding(self, commit: git.Commit, file_path: str, heuristic_finding: Dict[str, Any], finding_type: str = 'heuristic_detected_secret') -> Optional[Dict[str, Any]]:
        unique_id = f"{commit.hexsha}:{file_path}:{heuristic_finding['secret_value']}"
        
        if unique_id in self.seen_secrets:
            self.heuristic_duplicates_count += 1
            self.duplicates_count += 1
            return None
            
        self.seen_secrets.add(unique_id)
        finding = self.create_heuristic_finding(commit, file_path, heuristic_finding, finding_type)
        self.findings.append(finding)
        return finding
    
    def _create_base_finding(self, commit: git.Commit, file_path: str) -> Dict[str, Any]:
        return {
            'commit_hash': commit.hexsha,
            'author': str(commit.author),
            'date': str(commit.committed_datetime),
            'file_path': file_path
        }
    
    def create_llm_finding(self, commit: git.Commit, file_path: str, secret: Dict[str, Any], model_name: str) -> Dict[str, Any]:
        finding = self._create_base_finding(commit, file_path)
        
        if 'adjusted_confidence' in secret:
            confidence = secret['adjusted_confidence']
        else:
            confidence = self.heuristic_filter.calculate_confidence(
                secret['key'], 
                secret['value'],
                secret.get('type', 'llm_detected_secret')
            )
        
        finding.update({
            'finding_type': 'llm_detected_secret',
            'model': model_name,
            'secret_key': secret['key'],
            'secret_value': secret['value'],
            'confidence': round(confidence, 2)
        })
        
        if 'filtered_reason' in secret:
            finding['filtered_reason'] = secret['filtered_reason']
            
        return finding
    
    def create_heuristic_finding(self, commit: git.Commit, file_path: str, heuristic_finding: Dict[str, Any], finding_type: str = 'heuristic_detected_secret') -> Dict[str, Any]:
        finding = self._create_base_finding(commit, file_path)
        
        confidence = self.heuristic_filter.calculate_confidence(
            heuristic_finding['secret_key'],
            heuristic_finding['secret_value'],
            heuristic_finding.get('pattern_type')
        )
        
        finding.update({
            'line_number': heuristic_finding['line_number'],
            'snippet': heuristic_finding['line'],
            'finding_type': finding_type,
            'pattern': heuristic_finding['pattern_type'],
            'secret_key': heuristic_finding['secret_key'],
            'secret_value': heuristic_finding['secret_value'],
            'entropy': round(heuristic_finding['entropy'], 2),
            'confidence': round(confidence, 2)
        })
        return finding
    
    def get_findings(self) -> List[Dict[str, Any]]:
        return self.findings
    
    def get_false_positives(self) -> List[Dict[str, Any]]:
        return self.filtered_false_positives
    
    def save_report(self, repository: str, scan_mode: str, commits_count: int, findings: List[Dict[str, Any]], output_path: str, false_positives: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        report = {
            'repository': repository,
            'scan_mode': scan_mode,
            'commits_scanned': commits_count,
            'findings': findings
        }
        
        if false_positives:
            report['filtered_false_positives'] = false_positives
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def save_report_with_false_positives(self, repository: str, scan_mode: str, commits_count: int, findings: List[Dict[str, Any]], false_positives: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
        return self.save_report(repository, scan_mode, commits_count, findings, output_path, false_positives)
    
    def save_current_report(self, repository: str, scan_mode: str, commits_count: int, output_path: str) -> Dict[str, Any]:
        return self.save_report(
            repository, scan_mode, commits_count, 
            self.findings, output_path, 
            self.filtered_false_positives if self.filtered_false_positives else None
        )
    
    def print_summary(self, findings: List[Dict[str, Any]], scan_mode: str) -> None:
        llm_secrets_count = sum(1 for f in findings if 'llm_detected' in f.get('finding_type', ''))
        heuristic_secrets_count = sum(1 for f in findings if f.get('finding_type', '') == 'heuristic_detected_secret')
        heuristic_fallback_count = sum(1 for f in findings if 'heuristic_fallback' in f.get('finding_type', ''))
        llm_validated_count = sum(1 for f in findings if 'llm_validated' in f.get('finding_type', ''))
        
        logger.info("Analysis Summary:")
        if scan_mode == 'llm-only':
            logger.info(f"  - LLM detected: {llm_secrets_count} unique secret(s)")
            if self.llm_duplicates_count > 0:
                logger.info(f"  - Duplicates filtered: {self.llm_duplicates_count}")
        elif scan_mode == 'heuristic-only':
            logger.info(f"  - Heuristic detected: {heuristic_secrets_count} unique secret(s)")
            if self.heuristic_duplicates_count > 0:
                logger.info(f"  - Duplicates filtered: {self.heuristic_duplicates_count}")
        elif scan_mode == 'llm-fallback':
            logger.info(f"  - LLM detected: {llm_secrets_count} unique secret(s)")
            logger.info(f"  - Heuristic fallback detected: {heuristic_fallback_count} additional secret(s)")
            if self.duplicates_count > 0:
                logger.info(f"  - Total duplicates filtered: {self.duplicates_count}")
        elif scan_mode == 'llm-validated':
            logger.info(f"  - LLM validated secrets: {llm_validated_count} unique secret(s)")
            if self.llm_duplicates_count > 0:
                logger.info(f"  - Duplicates filtered: {self.llm_duplicates_count}")
    
    def print_current_summary(self, scan_mode: str) -> None:
        self.print_summary(self.findings, scan_mode)
        
        if scan_mode == 'llm-validated' and self.filtered_false_positives:
            logger.info(f"  - False positives removed: {len(self.filtered_false_positives)}")
