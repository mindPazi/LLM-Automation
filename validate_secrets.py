import json
import os
import re
from typing import Dict, Set, Tuple

def extract_all_ground_truth():
    """Extract ALL 68 ground truth secrets from the annotated file."""
    ground_truth = {}
    
    with open('tests/integration/test_large_codebase_annotated.py', 'r') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        # Pattern 1: variable = "value"  # TRUE/FALSE
        match = re.search(r'(\w+)\s*=\s*["\']([^"\']+)["\'].*#\s*(TRUE|FALSE)', line)
        
        # Pattern 2: "key": "value"  # TRUE/FALSE (in dictionaries)
        if not match:
            match = re.search(r'["\'](\w+)["\']:\s*["\']([^"\']+)["\'].*#\s*(TRUE|FALSE)', line)
        
        # Pattern 3: os.environ['KEY'] = "value"  # TRUE/FALSE
        if not match:
            match = re.search(r'os\.environ\[["\'](\w+)["\']\]\s*=\s*["\']([^"\']+)["\'].*#\s*(TRUE|FALSE)', line)
        
        if match:
            key = match.group(1)
            value = match.group(2)
            is_true = match.group(3) == 'TRUE'
            ground_truth[f"{key}:{value}"] = is_true
    
    # Handle multiline strings (private_key and test_cert)
    # These are special cases that span multiple lines
    if 'private_key' not in [k.split(':')[0] for k in ground_truth.keys()]:
        # Add the private key (TRUE)
        ground_truth["private_key:-----BEGIN RSA PRIVATE KEY-----"] = True
    
    if 'test_cert' not in [k.split(':')[0] for k in ground_truth.keys()]:
        # Add the test certificate (FALSE)
        ground_truth["test_cert:-----BEGIN CERTIFICATE-----"] = False
    
    return ground_truth

def load_json_files():
    """Load secrets from JSON output files."""
    modes = ['llm-only', 'heuristic-only', 'llm-validated']
    all_secrets = {}
    mode_secrets = {}
    
    for mode in modes:
        filepath = f'output/{mode}.json'
        mode_secrets[mode] = set()
        
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                
                # Extract findings
                for finding in data.get('findings', []):
                    if 'tests/integration/test_large_codebase' in finding['file_path']:
                        secret_id = f"{finding['secret_key']}:{finding['secret_value']}"
                        all_secrets[secret_id] = finding
                        mode_secrets[mode].add(secret_id)
    
    return all_secrets, mode_secrets

def calculate_metrics(mode_secrets: Dict[str, Set[str]], ground_truth: Dict[str, bool]):
    """Calculate metrics for each detection mode."""
    results = {}
    
    # We know the total: 27 TRUE and 41 FALSE = 68 total
    total_true_secrets = 27
    total_false_secrets = 41
    
    for mode, detected_secrets in mode_secrets.items():
        tp = 0  # True Positives: TRUE secrets correctly found
        fp = 0  # False Positives: FALSE secrets incorrectly found
        tn = 0  # True Negatives: FALSE secrets correctly not found
        fn = 0  # False Negatives: TRUE secrets incorrectly not found
        
        # Track which ground truth secrets were matched
        gt_matched = set()
        
        # Check each detected secret
        for detected in detected_secrets:
            found_match = False
            
            # Try to match with ground truth
            for gt_secret, is_real in ground_truth.items():
                # Skip if already matched
                if gt_secret in gt_matched:
                    continue
                    
                # Flexible matching: check if keys/values overlap
                detected_key = detected.split(':')[0]
                detected_val = detected.split(':', 1)[1] if ':' in detected else ''
                gt_key = gt_secret.split(':')[0]
                gt_val = gt_secret.split(':', 1)[1] if ':' in gt_secret else ''
                
                # Match if keys match and values are similar
                if (detected_key == gt_key or 
                    detected in gt_secret or 
                    gt_secret in detected or
                    (detected_val and gt_val and (detected_val in gt_val or gt_val in detected_val))):
                    
                    found_match = True
                    gt_matched.add(gt_secret)
                    
                    if is_real:
                        tp += 1  # Found a TRUE secret
                    else:
                        fp += 1  # Found a FALSE secret
                    break
        
        # Count secrets not found
        for gt_secret, is_real in ground_truth.items():
            if gt_secret not in gt_matched:
                if is_real:
                    fn += 1  # Missed a TRUE secret
                else:
                    tn += 1  # Correctly didn't find a FALSE secret
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / total_true_secrets if total_true_secrets > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (total_true_secrets + total_false_secrets)
        
        # Verify totals
        total_calculated = tp + fp + tn + fn
        
        results[mode] = {
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'total': total_calculated,
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'accuracy': round(accuracy, 3)
        }
    
    return results

def main():
    print("Extracting ALL ground truth from annotated file...")
    ground_truth = extract_all_ground_truth()
    
    total_true = sum(1 for v in ground_truth.values() if v)
    total_false = sum(1 for v in ground_truth.values() if not v)
    print(f"Ground truth: {len(ground_truth)} secrets ({total_true} TRUE, {total_false} FALSE)")
    
    if len(ground_truth) != 68:
        print(f"WARNING: Expected 68 secrets but found {len(ground_truth)}")
        print("Continuing with known totals: 27 TRUE, 41 FALSE")
    
    print("\nLoading secrets from JSON files...")
    all_secrets, mode_secrets = load_json_files()
    
    for mode, secrets in mode_secrets.items():
        print(f"{mode}: {len(secrets)} secrets detected")
    
    print("\nCalculating metrics (considering all 68 secrets)...")
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
        print(f"Total: {metrics['total']} (should be 68)")
        print(f"Precision:       {metrics['precision']}")
        print(f"Recall:          {metrics['recall']}")
        print(f"F1 Score:        {metrics['f1_score']}")
        print(f"Accuracy:        {metrics['accuracy']}")
    
    # Save results
    with open('output/metrics_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to output/metrics_results.json")

if __name__ == "__main__":
    main()
