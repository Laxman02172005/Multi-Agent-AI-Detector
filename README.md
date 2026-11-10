# Multi-Agent AI Phishing Email Detector

A modular, multi-agent Python system for detecting phishing emails using AI.

## Project Status

> **Task 1 Complete** — Project scaffold and environment initialized.
> Further tasks pending approval.

---

## Technology Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Language | Python 3.11+ | Modern typing, `tomllib`, async support |
| Environment | `venv` | Standard, no extra tooling required |
| Version Control | Git | Local-first, standard SCM |

> Additional stack components (NLP, agents, API, database, frontend) will be added per task approval.

---

## Project Structure

```
phishing-detector/
├── app/
│   ├── ingestion/      # Email parsing and ingestion logic
│   ├── schemas/        # Pydantic data models / schemas
│   └── utils/          # Shared utility functions
├── data/
│   ├── raw/            # Raw email files (never committed)
│   ├── processed/      # Processed/structured data (never committed)
│   └── samples/        # Anonymised test samples (never committed)
├── tests/              # Unit and integration tests
├── scripts/            # Standalone helper/utility scripts
├── .env.example        # Template for environment variables
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Environment Setup

### Prerequisites

- Python 3.11+
- pip
- Git

### 1. Clone / enter the project

```powershell
cd phishing-detector
```

### 2. Create the virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the virtual environment (Windows PowerShell)

```powershell
.venv\Scripts\Activate.ps1
```

> If you get an execution policy error, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

### 5. Configure environment variables

```powershell
Copy-Item .env.example .env
# Then edit .env with your actual values
```

---

## Running Tests

```powershell
pytest tests/
```

---

## Git Workflow

```powershell
git status
git add .
git commit -m "your message"
```

---

## Security Notes

- **Never** commit `.env` files or real email data.
- `data/raw/`, `data/processed/`, and `data/samples/` are excluded from Git via `.gitignore`.
- Use `.env.example` as the only committed environment template.
