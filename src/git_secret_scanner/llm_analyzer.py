import os
import re
from typing import Optional, List, Dict, Any
from openai import OpenAI

class LLMAnalyzer:
    
    def __init__(self, model_name: str = "gpt-5-mini", api_key: Optional[str] = None) -> None:
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.client = None
        
        if not self.api_key:
            raise ValueError("API key not provided. Set OPENAI_API_KEY environment variable or pass api_key parameter.")
    
    def load_model(self) -> None:
        self.client = OpenAI(api_key=self.api_key)
    
    def extract_findings(self, llm_response: str) -> List[Dict[str, Any]]:
        findings = []
        
        if not llm_response or "Error" in llm_response:
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
            return []
        
        return findings
    
    def analyze_diff(self, diff_content: str) -> str:
        if not self.client:
            raise ValueError("OpenAI client not initialized. Call load_model() first.")
        
        prompt = f"""Find secrets in this code:
{diff_content}

Return format:
KEY : VALUE

Example:
database_password : mySecretPassword123
api_key : sk-1234567890abcdef"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "Find secrets. Return KEY : VALUE format only."},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=16384
            )
            
            result = response.choices[0].message.content
            return result if result else "No response from LLM"
            
        except Exception as e:
            return f"Error analyzing diff: {str(e)}"
    
    def analyze_commit_message(self, message: str) -> str:
        if not self.client:
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
                    {"role": "system", "content": "You are a security expert. Extract and return ONLY actual secrets in KEY : VALUE format."},
                    {"role": "user", "content": prompt}
                ],
                max_completion_tokens=256
            )
            
            result = response.choices[0].message.content
            return result
            
        except Exception as e:
            return f"Error analyzing commit message: {str(e)}"
