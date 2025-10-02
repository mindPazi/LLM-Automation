# Git Secret Scanner

A comprehensive tool to scan Git repositories for potential secrets or sensitive data using advanced LLM models and heuristic filtering.

## Description

This project provides a CLI tool that analyzes Git repository commits to detect potential secrets or sensitive information using multiple detection methods including Large Language Models (LLM) and heuristic pattern matching.

Currently implements:
- **Multiple Scan Modes**: LLM-only, heuristic-only, LLM-fallback, and LLM-validated scanning
- **Advanced Pattern Recognition**: Regex-based heuristic filters with entropy analysis and confidence scoring
- **LLM Integration**: OpenAI GPT model integration for sophisticated secret detection
- **JSON Structure Support**: Enhanced detection for multiline secrets and JSON-embedded credentials
- **Comprehensive Reporting**: Detailed JSON reports with confidence scores and deduplication
- **Flexible Filtering**: Configurable file filters and test exclusion
- **Logging**: Comprehensive logging with configurable levels

## Installation

```bash
# Clone the repository
git clone https://github.com/mindPazi/LLM-Automation.git
cd LLM-Automation

# Install dependencies
pip install -r requirements.txt

# Set up OpenAI API key (required for LLM modes)
export OPENAI_API_KEY="your-api-key-here"
```

## Usage

### Basic Usage

```bash
# Scan last 5 commits using LLM-fallback mode (default)
python -m src.git_secret_scanner.cli --last 5

# Scan a specific commit range
python -m src.git_secret_scanner.cli --from HEAD~10 --to HEAD

# Scan with LLM-only mode
python -m src.git_secret_scanner.cli --last 5 --mode llm-only

# Scan with heuristic-only mode (no API key required)
python -m src.git_secret_scanner.cli --last 5 --mode heuristic-only
```

### Advanced Usage

```bash
# Complete example with all options
python -m src.git_secret_scanner.cli \
  --repo /path/to/repo \
  --from abc123 \
  --to def456 \
  --mode llm-validated \
  --model gpt-4 \
  --out findings.json \
  --log-level DEBUG \
  --log-file scan.log
```

### Parameters

#### Required Parameters (one of these):
- `--last N`: Scan last N commits
- `--from COMMIT`: Start commit (hash or reference)

#### Optional Parameters:
- `--repo PATH`: Path to the Git repository (default: '.')
- `--to COMMIT`: End commit (hash or reference, used with --from)
- `--out FILE`: Output file for the JSON report (default: 'report.json')
- `--mode MODE`: Scan mode (default: 'llm-fallback')
  - `llm-only`: Uses only LLM for detection
  - `heuristic-only`: Uses only heuristic patterns (no API key required)
  - `llm-fallback`: Uses LLM first, falls back to heuristics if no secrets found
  - `llm-validated`: Uses heuristics to filter LLM false positives
- `--model MODEL`: LLM model name (default: 'gpt-5')
- `--log-level LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL, default: INFO)
- `--log-file FILE`: Log file path (optional, logs to console by default)

## Scan Modes Explained

### 1. LLM-Only Mode (`--mode llm-only`)
- Uses OpenAI GPT models exclusively for secret detection
- Most accurate for complex secrets but requires API credits
- Best for: Production scanning where accuracy is critical

### 2. Heuristic-Only Mode (`--mode heuristic-only`)
- Uses regex patterns and entropy analysis
- No API key required, fastest execution
- Best for: Quick scans, CI/CD pipelines, or when API access is unavailable

### 3. LLM-Fallback Mode (`--mode llm-fallback`) - **Default**
- Tries LLM first, uses heuristics if LLM finds nothing
- Balanced approach between accuracy and coverage
- Best for: General-purpose scanning

### 4. LLM-Validated Mode (`--mode llm-validated`)
- Uses heuristics to pre-filter, then LLM validates findings
- Reduces false positives while maintaining high accuracy
- Best for: High-confidence results with minimal false positives

## Report Structure

The generated JSON report contains findings with different structures depending on the detection method:

### LLM-detected secrets:
- Include `model` field and calculated `confidence`
- No line-specific information since LLM analyzes content contextually

### Heuristic-detected secrets:
- Include `line_number`, `snippet`, `pattern`, and `entropy` fields
- More granular information about where and how the secret was found

```json
{
  "repository": ".",
  "scan_mode": "llm-fallback",
  "commits_scanned": 3,
  "findings": [
    {
      "commit_hash": "abc123...",
      "author": "Author Name",
      "date": "2025-09-28 15:14:08+02:00",
      "file_path": "config/settings.py",
      "finding_type": "llm_detected_secret",
      "model": "gpt-5",
      "secret_key": "api_key",
      "secret_value": "sk-proj-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z",
      "confidence": 0.95
    },
    {
      "commit_hash": "def456...",
      "author": "Author Name",
      "date": "2025-09-28 15:14:08+02:00",
      "file_path": "src/example.py",
      "line_number": 25,
      "snippet": "DATABASE_PASSWORD = \"P@ssw0rd!2024#DB\"",
      "finding_type": "heuristic_detected_secret",
      "pattern": "password",
      "secret_key": "DATABASE_PASSWORD",
      "secret_value": "P@ssw0rd!2024#DB",
      "entropy": 4.2,
      "confidence": 0.78
    }
  ],
  "llm_low_confidence_secrets": [
    {
      "commit_hash": "ghi789...",
      "author": "Author Name", 
      "date": "2025-09-28 15:14:08+02:00",
      "file_path": "test_file.py",
      "finding_type": "llm_low_confidence",
      "model": "gpt-5",
      "secret_key": "password",
      "secret_value": "password123",
      "confidence": 0.25,
      "filtered_reason": "Confidence too low: 0.25 < 0.5"
    }
  ]
}
```

## Configuration

The tool uses a `config.yaml` file for advanced configuration including:
- LLM settings (model, prompts, token limits)
- Heuristic patterns and thresholds
- File filtering rules
- Confidence calculation parameters
- Validation settings

## File Filtering

By default, the scanner excludes:
- Files in `output/` directory
- Files in `tests/unit/` directory  
- JSON report files (`*_test.json`, `*_report.json`)
- README files
- The `config.yaml` file itself

## Features

### Advanced Pattern Recognition
- **Multiline Support**: Detects secrets spanning multiple lines
- **JSON Parsing**: Extracts secrets from JSON structures (e.g., GCP service account keys)
- **Entropy Analysis**: Uses randomness scoring to identify potential secrets
- **Known Patterns**: Recognizes common secret formats (AWS keys, GitHub tokens, etc.)

### Confidence Scoring
- Dynamic confidence calculation based on multiple factors
- Pattern strength, entropy, length, and context analysis
- Configurable thresholds to balance false positives vs. false negatives

### Deduplication
- Automatic removal of duplicate findings across commits
- Hash-based detection to avoid reporting the same secret multiple times

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test categories
python -m pytest tests/unit/           # Unit tests
python -m pytest tests/integration/    # Integration tests

# Run individual test files
python -m pytest tests/integration/test_cli_end_to_end.py        # CLI end-to-end tests
python -m pytest tests/integration/test_scan_modes.py           # Scan mode integration tests
python -m pytest tests/integration/test_git.py                 # Git integration tests
python -m pytest tests/integration/test_large_codebase.py       # Large dataset tests
```

## Requirements

- Python 3.7+
- OpenAI API key (for LLM modes)
- Git repository access
- Dependencies listed in `requirements.txt`

## Notes

- **Security**: Never commit real API keys or secrets to the repository
- **Performance**: LLM modes consume API credits; use heuristic-only for frequent scans
- **Accuracy**: LLM-validated mode provides the best balance of accuracy and performance
- **Testing**: The scanner excludes unit test files by default but scans integration test files
