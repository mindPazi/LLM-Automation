# Git Secret Scanner

A simple tool to scan Git repositories for potential secrets or sensitive data.

## Description

This project provides a CLI command that analyzes Git repository commits to detect potential secrets or sensitive information.

Currently implements:
- Reading the last N commits from a Git repository
- Searching for suspicious keywords in commit messages
- Scanning file diffs for sensitive data in added lines
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
# Scan a single commit
python3 scan.py --from HEAD

# Scan commits between two references
python3 scan.py --from HEAD~5 --to HEAD

# Scan commits between specific hashes
python3 scan.py --from abc123 --to def456

# Complete example
python3 scan.py --repo /path/to/repo --from main~10 --to main --out findings.json
```

### Parameters

- `--repo`: Path to the Git repository (default: '.')
- `--from`: Start commit (hash or reference) - REQUIRED
- `--to`: End commit (hash or reference) - Optional, if not provided only the --from commit is scanned
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
    },
    {
      "commit_hash": "def456...",
      "author": "Author Name",
      "date": "2025-09-25 10:00:00",
      "file_path": "config/settings.py",
      "line_number": 42,
      "snippet": "api_key = 'sk-1234567890abcdef'",
      "finding_type": "suspicious_keyword_in_diff",
      "pattern": "api_key",
      "confidence": 0.5
    }
  ]
}
```

## Notes for Future Development

This is an early-stage project. Future implementations may include:
- Integration with LLM models for more sophisticated analysis
- Heuristic filters (regex, entropy) to reduce false positives
- Support for different types of secrets (API keys, certificates, etc.)

## License

This project is licensed under the MIT License.
