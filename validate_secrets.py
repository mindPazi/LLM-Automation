import json
import os
import re
from typing import Dict, Set

def extract_ground_truth_from_annotated():
    ground_truth = {}
    
    with open('tests/integration/test_large_codebase_annotated.py', 'r') as f:
        lines = f.readlines()
    
    for _, line in enumerate(lines, 1):
        match = re.search(r'(\w+)\s*=\s*["\']([^"\']+)["\'].*#\s*(TRUE|FALSE)', line)
        if not match:
            match = re.search(r'["\'](\w+)["\']:\s*["\']([^"\']+)["\'].*#\s*(TRUE|FALSE)', line)
        
        if match:
            key = match.group(1)
            value = match.group(2)
            is_true = match.group(3) == 'TRUE'
            ground_truth[f"{key}:{value}"] = is_true
    
    return ground_truth

def load_json_files():
    modes = ['llm-only', 'heuristic-only', 'llm-validated']
    all_secrets = {}
    mode_secrets = {}
    
    for mode in modes:
        filepath = f'output/{mode}.json'
        mode_secrets[mode] = set()
        
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                
                seen_secrets = set()
                
                for finding in data.get('findings', []):
                    if 'tests/integration/test_large_codebase' in finding['file_path']:
                        secret_value = finding['secret_value'].replace('...', '')
                        
                        secret_id = f"{finding['secret_key']}:{finding['secret_value']}"
                        all_secrets[secret_id] = finding
                        mode_secrets[mode].add(secret_id)
                
                for finding in data.get('llm_low_confidence_secrets', []):
                    if 'tests/integration/test_large_codebase' in finding['file_path']:
                        secret_id = f"{finding['secret_key']}:{finding['secret_value']}"
                        all_secrets[secret_id] = finding
                
                for finding in data.get('heuristic_low_confidence_secrets', []):
                    if 'tests/integration/test_large_codebase' in finding['file_path']:
                        secret_id = f"{finding['secret_key']}:{finding['secret_value']}"
                        all_secrets[secret_id] = finding
                
                for finding in data.get('heuristic_filtered_false_positives', []):
                    if 'tests/integration/test_large_codebase' in finding['file_path']:
                        secret_id = f"{finding['secret_key']}:{finding['secret_value']}"
                        all_secrets[secret_id] = finding
    
    return all_secrets, mode_secrets

def calculate_metrics(mode_secrets: Dict[str, Set[str]], ground_truth: Dict[str, bool]):
    results = {}
    total_secrets = 68
    
    for mode, detected_secrets in mode_secrets.items():
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        
        detected_matched = set()
        
        for detected in detected_secrets:
            found_match = False
            for gt_secret, is_real in ground_truth.items():
                if detected in gt_secret or gt_secret in detected:
                    found_match = True
                    detected_matched.add(gt_secret)
                    if is_real:
                        tp += 1
                    else:
                        fp += 1
                    break
        
        for gt_secret, is_real in ground_truth.items():
            if gt_secret not in detected_matched:
                if is_real:
                    fn += 1
                else:
                    tn += 1
        
        missing_secrets = total_secrets - len(ground_truth)
        tn += missing_secrets
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        
        results[mode] = {
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'accuracy': round(accuracy, 3)
        }
    
    return results

def main():
    print("Extracting ground truth from annotated file...")
    ground_truth = extract_ground_truth_from_annotated()
    
    total_true = sum(1 for v in ground_truth.values() if v)
    total_false = sum(1 for v in ground_truth.values() if not v)
    print(f"Found {len(ground_truth)} ground truth secrets: {total_true} TRUE, {total_false} FALSE")
    
    print("\nLoading secrets from JSON files...")
    all_secrets, mode_secrets = load_json_files()
    
    for mode, secrets in mode_secrets.items():
        print(f"{mode}: {len(secrets)} secrets detected")
    
    print("\nCalculating metrics...")
    results = calculate_metrics(mode_secrets, ground_truth)
    
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    
    for mode, metrics in results.items():
        print(f"\n{mode.upper()}")
        print("-"*40)
        print(f"True Positives:  {metrics['true_positives']}")
        print(f"False Positives: {metrics['false_positives']}")
        print(f"True Negatives:  {metrics['true_negatives']}")
        print(f"False Negatives: {metrics['false_negatives']}")
        print(f"Precision:       {metrics['precision']}")
        print(f"Recall:          {metrics['recall']}")
        print(f"F1 Score:        {metrics['f1_score']}")
        print(f"Accuracy:        {metrics['accuracy']}")
    
    with open('output/metrics_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to output/metrics_results.json")

if __name__ == "__main__":
    main()
