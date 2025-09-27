# Git Secret Scanner

A simple tool to scan Git repositories for potential secrets or sensitive data.

## Description

This project provides a CLI command that analyzes Git repository commits to detect potential secrets or sensitive information.

Currently implements:
- Reading the last N commits from a Git repository
- Searching for suspicious keywords in commit messages
- Generating JSON reports with the results

## Installation

```bash
# Clone the repository
git clone https://github.com/mindPazi/LLM-Automation.git
cd LLM-Automation

# Install dependencies
pip3 install gitpython
```

## Usage

```bash
# Scan the current repository (last 10 commits)
python3 scan.py

# Scan the last 20 commits and save the report
python3 scan.py --repo . --n 20 --out report.json

# Complete example
python3 scan.py --repo /path/to/repo --n 5 --out findings.json
```

### Parameters

- `--repo`: Path to the Git repository (default: '.')
- `--n`: Number of commits to analyze (default: 10)
- `--out`: Output file for the JSON report (default: 'report.json')

## Report Structure

The generated JSON report contains:
```json
{
  "repository": "path/to/repo",
  "commits_scanned": 10,
  "findings": [
    {
      "commit_hash": "abc123...",
      "author": "Author Name",
      "date": "2025-09-25 10:00:00",
      "message": "Commit message",
      "finding_type": "suspicious_keyword_in_message",
      "pattern": "password",
      "confidence": 0.3
    }
  ]
}
```

## Notes for Future Development

This is an early-stage project. Future implementations may include:
- Analysis of modified file content (diffs)
- Integration with LLM models for more sophisticated analysis
- Heuristic filters (regex, entropy) to reduce false positives
- Support for different types of secrets (API keys, certificates, etc.)

## License

This project is licensed under the MIT License.
