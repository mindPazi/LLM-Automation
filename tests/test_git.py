#!/usr/bin/env python3

from src.git_secret_scanner.git_handler import GitHandler

def test_read_commits():
    print("Test: Reading the last commits from the current repository\n")
    
    try:
        handler = GitHandler(".")
        
        commits = handler.get_recent_commits(5)
        
        print(f"Found {len(commits)} commits:\n")
        
        for commit in commits:
            print(f"Commit: {commit.hexsha[:8]}")
            print(f"Author: {commit.author.name}")
            print(f"Date: {commit.committed_datetime}")
            print(f"Message: {commit.message.strip()}")
            print("-" * 50)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_read_commits()
