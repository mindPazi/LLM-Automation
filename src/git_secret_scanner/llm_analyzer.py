from transformers import AutoTokenizer, AutoModelForCausalLM

class LLMAnalyzer:
    
    def __init__(self, model_name="llama"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
    
    def load_model(self):
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_name)
    
    def analyze_diff(self, diff_content):
        if not self.model or not self.tokenizer:
            raise ValueError("Model or tokenizer not loaded. Call load_model() first.")
        
        prompt = f"Analyze the following git diff for potential security issues or exposed secrets:\n\n{diff_content}"
        
        inputs = self.tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
        
        outputs = self.model.generate(
            inputs.input_ids,
            max_length=256,
            temperature=0.7,
            pad_token_id=self.tokenizer.eos_token_id
        )
        
        result = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        return result
    
    def analyze_commit_message(self, message):
        if not self.model or not self.tokenizer:
            raise ValueError("Model or tokenizer not loaded. Call load_model() first.")
        
        prompt = f"Analyze the following git commit message for potential security issues or exposed secrets:\n\n{message}"
        
        inputs = self.tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
        
        outputs = self.model.generate(
            inputs.input_ids,
            max_length=256,
            temperature=0.7,
            pad_token_id=self.tokenizer.eos_token_id
        )
        
        result = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        return result
