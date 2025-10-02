import yaml
from typing import Dict, Any
import os

class ConfigLoader:
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.load_config()
    
    def load_config(self, config_path: str = "config.yaml") -> None:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f)
        else:
            self._config = self._get_default_config()
    
    def get(self, *keys: str, default: Any = None) -> Any:
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'llm': {
                'default_model': 'gpt-5-mini',
                'max_completion_tokens': 16384,
                'max_completion_tokens_message': 256,
                'system_prompt': 'Find secrets. Return KEY : VALUE format only.',
                'system_prompt_commit': 'You are a security expert. Extract and return ONLY actual secrets in KEY : VALUE format.'
            },
            'heuristics': {
                'entropy': {
                    'threshold': 4.5,
                    'min_entropy': 2.0,
                    'low_entropy_cutoff': 2.5,
                    'medium_entropy_cutoff': 3.0,
                    'high_entropy_cutoff': 4.0
                },
                'confidence': {
                    'base_confidence': 0.3,
                    'filter_threshold': 0.5
                }
            },
            'validation': {
                'min_secret_length': 6,
                'max_spaces': 5,
                'min_keyword_count_for_fp': 3
            },
            'cli': {
                'default_output': 'report.json',
                'default_mode': 'llm-fallback',
                'default_repo': '.'
            }
        }

config = ConfigLoader()
