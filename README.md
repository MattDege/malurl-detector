# Malicious URL/Domain Detector (Starter)

Cross-platform baseline using lexical features + Logistic Regression.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -e '.[dev]'
pre-commit install

pytest -q
python -m maldet.train --in data/raw/sample_urls.csv --out models/baseline.joblib
python -m maldet.predict --model models/baseline.joblib --in data/raw/sample_urls.csv --out data/processed/preds.csv
