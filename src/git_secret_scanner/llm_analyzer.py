import os
import re
import json
from typing import Optional, List, Dict, Any
import git
from openai import OpenAI
from src.git_secret_scanner.config_loader import config
from src.git_secret_scanner.logger_config import get_logger
from src.git_secret_scanner.heuristics import HeuristicFilter

logger = get_logger(__name__)

class LLMAnalyzer:
    
    def __init__(self, model_name: Optional[str] = None, api_key: Optional[str] = None) -> None:
        logger.info("Initializing LLMAnalyzer")
        self.model_name = model_name or config.get('llm', 'default_model')
        
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
        findings = []
        
        if not llm_response or "Error" in llm_response:
            return findings
        
        seen_findings = set()
        
        
        confidence_pattern = r'([A-Za-z_]+[A-Za-z0-9_]*)\s*:\s*([^:\n]+?)\s*:\s*(0(?:\.\d+)?|0\.25|0\.75|1(?:\.0)?)'
        confidence_matches = re.findall(confidence_pattern, llm_response)
        
        for key, value, confidence_str in confidence_matches:
            value = value.strip().strip('"\'')
            
            
            if len(value) <= 5 or value.startswith("***") or value == "hidden":
                continue
                
            
            try:
                confidence = float(confidence_str)
                
                if confidence <= 0.125:
                    confidence = 0.0
                elif confidence <= 0.5:
                    confidence = 0.25
                elif confidence <= 0.875:
                    confidence = 0.75
                else:
                    confidence = 1.0
            except ValueError:
                confidence = 0.25  
            
            unique_id = f"{key.lower()}:{value[:50]}"
            if unique_id not in seen_findings:
                seen_findings.add(unique_id)
                findings.append({
                    'key': key,
                    'value': value[:100],
                    'type': 'llm_detected_secret',
                    'confidence': confidence
                })
        
        
        if not findings:
            simple_pattern = r'([A-Za-z_]+[A-Za-z0-9_]*)\s*:\s*([^:\n]+?)(?:\n|$)'
            simple_matches = re.findall(simple_pattern, llm_response)
            
            for key, value in simple_matches:
                value = value.strip().strip('"\'')
                
                
                if len(value) <= 5 or value.startswith("***") or value == "hidden":
                    continue
                    
                
                if re.match(r'^\s*(0(?:\.\d+)?|0\.25|0\.75|1(?:\.0)?)\s*$', value):
                    continue
                
                unique_id = f"{key.lower()}:{value[:50]}"
                if unique_id not in seen_findings:
                    seen_findings.add(unique_id)
                    findings.append({
                        'key': key,
                        'value': value[:100],
                        'type': 'llm_detected_secret',
                        'confidence': 0.75  
                    })
        
        if re.search(r'no\s+(secrets?|issues?|problems?)\s+found', llm_response, re.IGNORECASE):
            return []
        
        return findings
    
    def analyze_diff(self, diff_content: str) -> str:
        if not self.client:
            logger.error("OpenAI client not initialized")
            raise ValueError("OpenAI client not initialized. Call load_model() first.")
        
        prompt = f"""Find secrets in this code:
{diff_content}

Return format:
KEY : VALUE : CONFIDENCE

Where CONFIDENCE must be one of these values:
- 0 = Definitely a false positive (test data, placeholder, example)
- 0.25 = Probably a false positive (low entropy, common pattern)
- 0.75 = Probably a real secret (high entropy, looks authentic)
- 1.0 = Definitely a real secret (matches known patterns, very high entropy)

Examples of REAL secrets (0.75 or 1.0):
database_password : mySecretPassword123 : 0.75
api_key : sk-1234567890abcdef : 1.0
aws_secret : AKIAIOSFODNN7EXAMPLE : 0.75

Examples of FALSE POSITIVES (0 or 0.25):
test_token : test-token-123 : 0
example_key : your-api-key-here : 0
placeholder : insert_your_token_here : 0
descriptive : final_bearer_token_with_sufficient_length : 0
readable_desc : this_is_the_secret_key : 0
fake_data : staging_demo_secret_value : 0.25
test_value : my_test_api_key_here : 0
human_text : password_goes_here : 0

IMPORTANT: If the value contains human-readable descriptions like "with_sufficient_length", "this_is_the", "put_your", "insert_here", etc., it's a FALSE POSITIVE (confidence = 0).

If no secrets found, respond with "No secrets found"."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": config.get('llm', 'system_prompt')},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=config.get('llm', 'max_completion_tokens')
            )
            
            result = response.choices[0].message.content
            return result if result else "No response from LLM"
            
        except Exception as e:
            logger.error(f"Error analyzing diff: {str(e)}")
            return f"Error analyzing diff: {str(e)}"
    
    def analyze_commit_message(self, message: str) -> str:
        if not self.client:
            logger.error("OpenAI client not initialized")
            raise ValueError("OpenAI client not initialized. Call load_model() first.")
        
        prompt = f"""Analyze the following git commit message for exposed secrets.
Return ONLY found secrets in the format KEY : VALUE, one per line.
If no secrets are found, respond with "No secrets found".

Commit message:
{message}"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": config.get('llm', 'system_prompt_commit')},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=config.get('llm', 'max_completion_tokens_message')
            )
            
            result = response.choices[0].message.content
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing commit message: {str(e)}")
            return f"Error analyzing commit message: {str(e)}"
    
    def analyze_lines(self, added_lines: List[str]) -> List[Dict[str, Any]]:
        diff_content = '\n'.join(added_lines)
        llm_result = self.analyze_diff(diff_content)
        findings = self.extract_findings(llm_result)
        return findings
    
    def _process_llm_secrets(self, llm_secrets: List[Dict[str, Any]], 
                                            commit: git.Commit,
                                            file_path: str, report_generator: Any, 
                                            model_name: str) -> int:
        unique_count = 0
        low_confidence_count = 0
        duplicate_count = 0
        
        for secret in llm_secrets:
            
            confidence = secret.get('confidence', 0.75)  
            
            if confidence < 0.5:
                secret['filtered_reason'] = f'LLM confidence too low: {confidence:.2f} < 0.5'
                result = report_generator.add_llm_finding(commit, file_path, secret, model_name, category='low_confidence')
                if result:
                    low_confidence_count += 1
            else:
                result = report_generator.add_llm_finding(commit, file_path, secret, model_name, category='raw')
                if result:
                    unique_count += 1
                else:
                    duplicate_count += 1
        
        if unique_count > 0:
            logger.info(f"LLM found {unique_count} high confidence secret(s) in {file_path}")
        if low_confidence_count > 0:
            logger.info(f"LLM filtered {low_confidence_count} low confidence secret(s) in {file_path}")
        if duplicate_count > 0:
            logger.info(f"  Duplicates filtered: {duplicate_count}")
            
        return unique_count
    
    def process_llm_only(self, added_lines: List[str], commit: git.Commit, 
                        file_path: str, report_generator: Any, model_name: str) -> int:
        
        llm_secrets = self.analyze_lines(added_lines)
        
        if llm_secrets:
            return self._process_llm_secrets(
                llm_secrets, commit, file_path, 
                report_generator, model_name
            )
        else:
            return 0
    
    def process_llm_validated(self, heuristic_filter: Any, added_lines: List[str], 
                             commit: git.Commit, file_path: str, 
                             report_generator: Any, model_name: str) -> int:
        llm_secrets = self.analyze_lines(added_lines)
        
        if not llm_secrets:
            return 0
        
        unique_secrets = []
        for secret in llm_secrets:
            unique_id = f"{commit.hexsha}:{file_path}:{secret['value']}"
            
            if unique_id not in report_generator.seen_secrets:
                unique_secrets.append(secret)
        
        validated_secrets = []
        false_positives = []
        
        for secret in unique_secrets:
            
            llm_confidence = secret.get('confidence', 0.75)
            
            
            if llm_confidence >= 0.5:
                
                heuristic_confidence = heuristic_filter.calculate_confidence(
                    secret['key'], 
                    secret['value'], 
                    secret.get('type')
                )
                
                
                
                final_confidence = (llm_confidence * 0.7) + (heuristic_confidence * 0.3)
                secret['adjusted_confidence'] = round(final_confidence, 2)
                
                if final_confidence >= 0.5:
                    validated_secrets.append(secret)
                else:
                    secret['filtered_reason'] = f'Combined confidence too low: {final_confidence:.2f} < 0.5'
                    false_positives.append(secret)
            else:
                
                secret['adjusted_confidence'] = llm_confidence
                secret['filtered_reason'] = f'LLM confidence too low: {llm_confidence:.2f} < 0.5'
                false_positives.append(secret)
        
        actually_added = 0
        for secret in validated_secrets:
            result = report_generator.add_llm_finding(commit, file_path, secret, model_name, category='validated')
            if result is not None:
                actually_added += 1
        
        false_positives_added = 0
        for secret in false_positives:
            result = report_generator.add_llm_finding(commit, file_path, secret, model_name, category='false_positive')
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
        llm_secrets = self.analyze_lines(added_lines)
        
        if llm_secrets:
            unique_count = self._process_llm_secrets(
                llm_secrets, commit, file_path, 
                report_generator, model_name
            )
            return unique_count
        
        
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
            return 0
