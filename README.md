# Privacy Posture Analyzer — Backend

## Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Server runs at http://localhost:8000
Interactive API docs at http://localhost:8000/docs

## File Structure

```
backend/
├── main.py              # FastAPI app + /upload endpoint
├── database.py          # SQLite engine + SessionLocal
├── models.py            # Audit + Tracker ORM models
├── requirements.txt     # Dependencies
└── modules/
    ├── __init__.py
    ├── trackers.py      # Member 2 — SDK/Tracker Detection (YOU)
    ├── permissions.py   # Member 1 — add here
    ├── report.py        # Member 3 — add here
    └── ai_classifier.py # Member 4 — add here
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /upload | Upload an APK file |
| POST | /analyze/trackers/{app_id} | Detect SDKs/trackers in APK |

## Workflow

1. Upload APK → `POST /upload` → get back `app_id`
2. Analyze → `POST /analyze/trackers/{app_id}` → get tracker list
