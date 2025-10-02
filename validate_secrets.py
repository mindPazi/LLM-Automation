import json
import os
from typing import Dict, Set, Tuple

def load_json_files():
    modes = ['llm-only', 'heuristic-only', 'llm-validated', 'llm-fallback']
    all_secrets = set()
    mode_secrets = {}
    
    for mode in modes:
        filepath = f'output/{mode}.json'
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                mode_secrets[mode] = set()
                
                for finding in data.get('findings', []):
                    secret_id = f"{finding['commit_hash']}:{finding['file_path']}:{finding.get('line_number', 'N/A')}:{finding['secret_key']}:{finding['secret_value']}"
                    all_secrets.add(secret_id)
                    mode_secrets[mode].add(secret_id)
                
                for finding in data.get('llm_low_confidence_secrets', []):
                    secret_id = f"{finding['commit_hash']}:{finding['file_path']}:{finding.get('line_number', 'N/A')}:{finding['secret_key']}:{finding['secret_value']}"
                    all_secrets.add(secret_id)
                
                for finding in data.get('heuristic_low_confidence_secrets', []):
                    secret_id = f"{finding['commit_hash']}:{finding['file_path']}:{finding.get('line_number', 'N/A')}:{finding['secret_key']}:{finding['secret_value']}"
                    all_secrets.add(secret_id)
                
                for finding in data.get('heuristic_filtered_false_positives', []):
                    secret_id = f"{finding['commit_hash']}:{finding['file_path']}:{finding.get('line_number', 'N/A')}:{finding['secret_key']}:{finding['secret_value']}"
                    all_secrets.add(secret_id)
    
    return all_secrets, mode_secrets

def collect_ground_truth(all_secrets: Set[str]):
    ground_truth = {}
    ground_truth_file = 'output/ground_truth.json'
    
    if os.path.exists(ground_truth_file):
        with open(ground_truth_file, 'r') as f:
            ground_truth = json.load(f)
    
    for secret_id in sorted(all_secrets):
        if secret_id not in ground_truth:
            parts = secret_id.split(':')
            commit = parts[0][:8]
            filepath = parts[1]
            line = parts[2]
            key = parts[3]
            value = parts[4]
            
            print(f"\n{'='*80}")
            print(f"Commit: {commit}")
            print(f"File: {filepath}")
            print(f"Line: {line}")
            print(f"Key: {key}")
            print(f"Value: {value}")
            print(f"{'='*80}")
            
            while True:
                response = input("Is this a real secret? (y/n): ").lower()
                if response in ['y', 'n']:
                    ground_truth[secret_id] = (response == 'y')
                    break
                print("Please enter 'y' or 'n'")
            
            with open(ground_truth_file, 'w') as f:
                json.dump(ground_truth, f, indent=2)
    
    return ground_truth

def calculate_metrics(mode_secrets: Dict[str, Set[str]], ground_truth: Dict[str, bool]):
    results = {}
    
    all_possible_secrets = set(ground_truth.keys())
    
    for mode, detected_secrets in mode_secrets.items():
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        
        for secret_id in all_possible_secrets:
            is_real_secret = ground_truth[secret_id]
            is_detected = secret_id in detected_secrets
            
            if is_real_secret and is_detected:
                tp += 1
            elif is_real_secret and not is_detected:
                fn += 1
            elif not is_real_secret and is_detected:
                fp += 1
            elif not is_real_secret and not is_detected:
                tn += 1
        
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
    print("Loading secrets from JSON files...")
    all_secrets, mode_secrets = load_json_files()
    
    print(f"\nFound {len(all_secrets)} unique secrets across all modes")
    
    print("\nCollecting ground truth labels...")
    ground_truth = collect_ground_truth(all_secrets)
    
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
