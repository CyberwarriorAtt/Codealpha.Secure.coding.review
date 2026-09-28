# Task 3: Secure Coding Review

- Language/app: Python + Flask sample app
- Full findings, CWE mapping and remediation: [`REPORT.md`](REPORT.md)
- Original vulnerable code: [`sample-app/vulnerable_app.py`](sample-app/vulnerable_app.py)
- Fixed code: [`sample-app/fixed_app.py`](sample-app/fixed_app.py)

## Reproduce the static analysis
```bash
pip install bandit
bandit -r sample-app/vulnerable_app.py
bandit -r sample-app/fixed_app.py
```

> `vulnerable_app.py` is intentionally insecure for training. Never deploy it or expose it to a network.
