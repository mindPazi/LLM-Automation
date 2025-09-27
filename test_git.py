#!/usr/bin/env python3

from git_secret_scanner.git_handler import GitHandler

def test_read_commits():
    print("Test: Lettura degli ultimi commit dal repository corrente\n")
    
    try:
        handler = GitHandler(".")
        
        commits = handler.get_recent_commits(5)
        
        print(f"Trovati {len(commits)} commit:\n")
        
        for commit in commits:
            print(f"Commit: {commit.hexsha[:8]}")
            print(f"Autore: {commit.author.name}")
            print(f"Data: {commit.committed_datetime}")
            print(f"Messaggio: {commit.message.strip()}")
            print("-" * 50)
            
    except Exception as e:
        print(f"Errore: {e}")

if __name__ == "__main__":
    test_read_commits()
