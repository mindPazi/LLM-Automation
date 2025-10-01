import os
import re
import json
from typing import Optional, List, Dict, Any
import git
from openai import OpenAI
from src.git_secret_scanner.config_loader import config
from src.git_secret_scanner.logger_config import get_logger

logger = get_logger(__name__)

class LLMAnalyzer:
    
    def __init__(self, model_name: Optional[str] = None, api_key: Optional[str] = None) -> None:
        logger.info("Initializing LLMAnalyzer")
        self.model_name = model_name or config.get('llm', 'default_model')
        logger.debug(f"Using model: {self.model_name}")
        
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.client = None
        
        if not self.api_key:
            logger.error("API key not provided")
            raise ValueError("API key not provided. Set OPENAI_API_KEY environment variable or pass api_key parameter.")
        
        logger.info("LLMAnalyzer initialized successfully")
    
    def load_model(self) -> None:
        logger.info("Loading OpenAI client")
        self.client = OpenAI(api_key=self.api_key)
        logger.info("OpenAI client loaded successfully")
    
    def extract_findings(self, llm_response: str) -> List[Dict[str, Any]]:
        logger.debug("Extracting findings from LLM response")
        findings = []
        
        if not llm_response or "Error" in llm_response:
            logger.debug("No response or error in LLM response")
            return findings
        
        seen_findings = set()
        
        
        
        json_pattern = r'([A-Za-z_]+[A-Z_]*[A-Za-z_]*)\s*:\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})'
        json_matches = re.findall(json_pattern, llm_response, re.DOTALL)
        
        for key, json_str in json_matches:
            try:
                
                json_data = json.loads(json_str)
                
                
                sensitive_fields = ['private_key', 'password', 'secret', 'token', 'api_key', 
                                   'client_secret', 'access_token', 'refresh_token']
                
                for field in sensitive_fields:
                    if field in json_data and json_data[field]:
                        field_value = str(json_data[field])
                        if len(field_value) > 5:
                            unique_id = f"{key}_{field}:{field_value[:50]}"
                            if unique_id not in seen_findings:
                                seen_findings.add(unique_id)
                                findings.append({
                                    'key': f"{key}_{field}",
                                    'value': field_value[:100],
                                    'type': 'llm_detected_secret'
                                })
                                logger.debug(f"Extracted {field} from JSON for key {key}")
                
                
                if not any(field in json_data for field in sensitive_fields):
                    json_str_short = json_str[:100]
                    unique_id = f"{key}:{json_str_short[:50]}"
                    if unique_id not in seen_findings:
                        seen_findings.add(unique_id)
                        findings.append({
                            'key': key,
                            'value': json_str_short,
                            'type': 'llm_detected_secret'
                        })
            except json.JSONDecodeError:
                
                logger.debug(f"Could not parse as JSON for key {key}, treating as string")
                unique_id = f"{key}:{json_str[:50]}"
                if unique_id not in seen_findings and len(json_str) > 5:
                    seen_findings.add(unique_id)
                    findings.append({
                        'key': key,
                        'value': json_str[:100],
                        'type': 'llm_detected_secret'
                    })
        
        
        patterns = [
            r'([A-Z_]+)\s*:\s*["\']?([^"\'\n]+)["\']?',
            r'([a-z_]+)\s*:\s*["\']?([^"\'\n]+)["\']?',
            r'([A-Za-z_]+[Kk]ey|[Tt]oken|[Pp]assword|[Ss]ecret|[Cc]redential)\s*:\s*["\']?([^"\'\n]+)["\']?'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, llm_response)
            for match in matches:
                key = match[0]
                value = match[1] if len(match) > 1 else match[0]
                
                
                if value.strip().startswith('{'):
                    continue
                
                if len(value) > 5 and not value.startswith("***") and not value == "hidden":
                    unique_id = f"{key.lower()}:{value}"
                    
                    if unique_id not in seen_findings:
                        seen_findings.add(unique_id)
                        findings.append({
                            'key': key,
                            'value': value[:100],
                            'type': 'llm_detected_secret'
                        })
        
        if re.search(r'no\s+(secrets?|issues?|problems?)\s+found', llm_response, re.IGNORECASE):
            logger.debug("LLM explicitly stated no secrets found")
            return []
        
        logger.debug(f"Extracted {len(findings)} findings from LLM response")
        return findings
    
    def analyze_diff(self, diff_content: str) -> str:
        if not self.client:
            logger.error("OpenAI client not initialized")
            raise ValueError("OpenAI client not initialized. Call load_model() first.")
        
        logger.debug(f"Analyzing diff with {len(diff_content)} characters")
        
        prompt = f"""Find secrets in this code:
{diff_content}

Return format:
KEY : VALUE

Example:
database_password : mySecretPassword123
api_key : sk-1234567890abcdef"""
        
        try:
            logger.debug(f"Sending request to {self.model_name}")
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": config.get('llm', 'system_prompt')},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=config.get('llm', 'max_completion_tokens')
            )
            
            result = response.choices[0].message.content
            logger.debug(f"Received response from LLM ({len(result) if result else 0} characters)")
            return result if result else "No response from LLM"
            
        except Exception as e:
            logger.error(f"Error analyzing diff: {str(e)}")
            return f"Error analyzing diff: {str(e)}"
    
    def analyze_commit_message(self, message: str) -> str:
        if not self.client:
            logger.error("OpenAI client not initialized")
            raise ValueError("OpenAI client not initialized. Call load_model() first.")
        
        logger.debug(f"Analyzing commit message: {message[:50]}...")
        
        prompt = f"""Analyze the following git commit message for exposed secrets.
Return ONLY found secrets in the format KEY : VALUE, one per line.
If no secrets are found, respond with "No secrets found".

Commit message:
{message}"""
        
        try:
            logger.debug(f"Sending commit message request to {self.model_name}")
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": config.get('llm', 'system_prompt_commit')},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=config.get('llm', 'max_completion_tokens_message')
            )
            
            result = response.choices[0].message.content
            logger.debug(f"Received commit message response from LLM")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing commit message: {str(e)}")
            return f"Error analyzing commit message: {str(e)}"
    
    def analyze_lines(self, added_lines: List[str]) -> List[Dict[str, Any]]:
        logger.debug(f"Analyzing {len(added_lines)} lines with LLM")
        diff_content = '\n'.join(added_lines)
        llm_result = self.analyze_diff(diff_content)
        findings = self.extract_findings(llm_result)
        logger.debug(f"LLM found {len(findings)} findings")
        return findings
    
    def process_llm_only(self, added_lines: List[str], commit: git.Commit, 
                        file_path: str, report_generator: Any, model_name: str) -> int:
        from src.git_secret_scanner.heuristics import HeuristicFilter
        
        llm_secrets = self.analyze_lines(added_lines)
        
        if llm_secrets:
            heuristic_filter = HeuristicFilter()
            
            unique_count = 0
            low_confidence_count = 0
            duplicate_count = 0
            
            for secret in llm_secrets:
                confidence = heuristic_filter.calculate_confidence(
                    secret['key'], 
                    secret['value'], 
                    secret.get('type')
                )
                secret['confidence'] = round(confidence, 2)
                
                if confidence < 0.5:
                    secret['filtered_reason'] = f'Confidence too low: {confidence:.2f} < 0.5'
                    result = report_generator.add_llm_low_confidence(commit, file_path, secret, model_name)
                    if result:
                        low_confidence_count += 1
                else:
                    result = report_generator.add_llm_finding(commit, file_path, secret, model_name)
                    if result:
                        unique_count += 1
                    else:
                        duplicate_count += 1
            
            if unique_count > 0 or low_confidence_count > 0:
                logger.info(f"LLM found {unique_count + low_confidence_count} secret(s) in {file_path}: {unique_count} high confidence, {low_confidence_count} low confidence (filtered)")
            if duplicate_count > 0:
                logger.info(f"  Duplicates filtered: {duplicate_count}")
            
            return unique_count
        else:
            logger.debug(f"LLM found no secrets in {file_path}")
            return 0
    
    def process_llm_validated(self, heuristic_filter: Any, added_lines: List[str], 
                             commit: git.Commit, file_path: str, 
                             report_generator: Any, model_name: str) -> int:
        llm_secrets = self.analyze_lines(added_lines)
        
        if not llm_secrets:
            logger.debug(f"LLM found no secrets in {file_path}")
            return 0
        
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
        
        return actually_added
    
    def process_llm_fallback(self, heuristic_filter: Any, added_lines: List[str], 
                            commit: git.Commit, file_path: str, 
                            report_generator: Any, model_name: str) -> int:
        llm_found_secrets = False
        unique_count = 0
        
        llm_secrets = self.analyze_lines(added_lines)
        
        if llm_secrets:
            llm_found_secrets = True
            low_confidence_count = 0
            duplicate_count = 0
            
            for secret in llm_secrets:
                confidence = heuristic_filter.calculate_confidence(
                    secret['key'], 
                    secret['value'], 
                    secret.get('type')
                )
                secret['confidence'] = round(confidence, 2)
                
                if confidence < 0.5:
                    secret['filtered_reason'] = f'Confidence too low: {confidence:.2f} < 0.5'
                    result = report_generator.add_llm_low_confidence(commit, file_path, secret, model_name)
                    if result:
                        low_confidence_count += 1
                else:
                    result = report_generator.add_llm_finding(commit, file_path, secret, model_name)
                    if result:
                        unique_count += 1
                    else:
                        duplicate_count += 1
            
            if unique_count > 0 or low_confidence_count > 0:
                logger.info(f"LLM found {unique_count + low_confidence_count} secret(s) in {file_path}: {unique_count} high confidence, {low_confidence_count} low confidence (filtered)")
            if duplicate_count > 0:
                logger.info(f"  Duplicates filtered: {duplicate_count}")
        
        if not llm_found_secrets:
            heuristic_results = heuristic_filter.apply_regex_filters(added_lines)
            
            if heuristic_results:
                unique_count = 0
                duplicate_count = 0
                for heuristic_finding in heuristic_results:
                    result = report_generator.add_heuristic_finding(commit, file_path, heuristic_finding, 
                                                                   'heuristic_fallback_secret')
                    if result:
                        unique_count += 1
                    else:
                        duplicate_count += 1
                
                if duplicate_count > 0:
                    logger.info(f"Heuristic found {len(heuristic_results)} secret(s) missed by LLM in {file_path} ({unique_count} unique, {duplicate_count} duplicates filtered)")
                else:
                    logger.info(f"Heuristic found {unique_count} unique secret(s) missed by LLM in {file_path}")
                
                return unique_count
            else:
                logger.debug(f"No secrets found in {file_path}")
                return 0
        
        return unique_count if llm_found_secrets else 0
