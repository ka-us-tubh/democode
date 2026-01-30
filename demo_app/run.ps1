$env:IAM_SECRET_KEY = "dev-secret-change-me"
$env:IAM_PASSWORD_SCHEMES = "pbkdf2_sha256"
python -m uvicorn demo_app.main:app --reload --port 8000
