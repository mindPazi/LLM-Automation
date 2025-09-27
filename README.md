# Git Secret Scanner

Un tool semplice per scansionare repository Git alla ricerca di potenziali segreti o dati sensibili.

## Descrizione

Questo progetto fornisce un comando CLI che analizza i commit di un repository Git per rilevare potenziali segreti o informazioni sensibili. 

Attualmente implementa:
- Lettura degli ultimi N commit da un repository Git
- Ricerca di parole chiave sospette nei messaggi di commit
- Generazione di report JSON con i risultati

## Installazione

```bash
# Clona il repository
git clone https://github.com/mindPazi/LLM-Automation.git
cd LLM-Automation

# Installa le dipendenze
pip3 install gitpython
```

## Utilizzo

```bash
# Scansiona il repository corrente (ultimi 10 commit)
python3 scan.py

# Scansiona gli ultimi 20 commit e salva il report
python3 scan.py --repo . --n 20 --out report.json

# Esempio completo
python3 scan.py --repo /path/to/repo --n 5 --out findings.json
```

### Parametri

- `--repo`: Path al repository Git (default: '.')
- `--n`: Numero di commit da analizzare (default: 10)
- `--out`: File di output per il report JSON (default: 'report.json')

## Struttura del Report

Il report JSON generato contiene:
```json
{
  "repository": "path/to/repo",
  "commits_scanned": 10,
  "findings": [
    {
      "commit_hash": "abc123...",
      "author": "Nome Autore",
      "date": "2025-09-25 10:00:00",
      "message": "Messaggio del commit",
      "finding_type": "suspicious_keyword_in_message",
      "pattern": "password",
      "confidence": 0.3
    }
  ]
}
```

## Note per lo Sviluppo Futuro

Questo è un progetto in fase iniziale. Le prossime implementazioni potrebbero includere:
- Analisi del contenuto dei file modificati (diff)
- Integrazione con modelli LLM per analisi più sofisticate
- Filtri euristici (regex, entropia) per ridurre i falsi positivi
- Supporto per diversi tipi di segreti (API keys, certificati, ecc.)

## License

This project is licensed under the MIT License.
