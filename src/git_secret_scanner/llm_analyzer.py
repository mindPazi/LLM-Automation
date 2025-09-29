import os
import re
from typing import Optional, List, Dict, Any
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
        
        patterns = [
            r'([A-Z_]+)\s*:\s*["\']?([^"\'\n]+)["\']?',
            r'([a-z_]+)\s*:\s*["\']?([^"\'\n]+)["\']?',
            r'([A-Za-z_]+[Kk]ey|[Tt]oken|[Pp]assword|[Ss]ecret|[Cc]redential)\s*:\s*["\']?([^"\'\n]+)["\']?'
        ]
        
        seen_findings = set()
        
        for pattern in patterns:
            matches = re.findall(pattern, llm_response)
            for match in matches:
                key = match[0]
                value = match[1] if len(match) > 1 else match[0]
                
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
