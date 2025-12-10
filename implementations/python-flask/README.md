# Python Flask Implementation

Flask 3.0 with SQLAlchemy 2.0

## Structure

```
python-flask/
├── vulnerable/         # Vulnerable implementation (string formatting)
│   ├── app.py
│   ├── requirements.txt
│   └── config.py
└── secured/           # Secured implementation (SQLAlchemy ORM)
    ├── app.py
    ├── models.py
    ├── requirements.txt
    └── config.py
```

## Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies (vulnerable version)
cd vulnerable
pip install flask pyodbc python-dotenv

# Install dependencies (secured version)
cd ../secured
pip install flask sqlalchemy pyodbc python-dotenv
```

## Environment Variables

Create `.env` file:
```
DATABASE_URL=mssql+pyodbc://localhost/SQLInjectionTest?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes
FLASK_ENV=development
```

## Run

```bash
# Vulnerable version (runs on http://localhost:5000)
cd vulnerable
python app.py

# Secured version (runs on http://localhost:5001)
cd secured
python app.py
```

## Key Differences

### Vulnerable
- Raw SQL with f-strings or % formatting
- Direct string interpolation
- Manual connection handling

### Secured
- SQLAlchemy ORM models
- Automatic query parameterization
- Session management
- SQL injection protection by default

