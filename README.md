# File Inspector

Lightweight static file analysis web service (FastAPI).
Upload a file → MD5/SHA-1/SHA-256, Shannon entropy (whole + per-4KiB block), magic-byte type detection, ELF header summary, printable strings.

## Run locally
```bash
pip install -r requirements.txt
uvicorn app:app --reload
# http://127.0.0.1:8000  (UI)   http://127.0.0.1:8000/docs (Swagger)
```

## Docker
```bash
docker build -t file-inspector .
docker run -d -p 8000:8000 --name file-inspector file-inspector
curl -F file=@/bin/ls http://127.0.0.1:8000/api/analyze
```

## CI/CD (HW3)
- `ci.yml`: on push to `main` → pytest → build image → push `<user>/file-inspector:latest` + `:<sha>` to Docker Hub
- `cd.yml`: triggered after CI succeeds → self-hosted runner pulls image, replaces container, health-checks `/api/health`
- Required repo secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
