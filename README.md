# STARLIGHT — Web CTF (Easy)

**Category:** Web | **Difficulty:** Easy  
**Concept:** JWT authentication bypass / trusting unverified claims  
**Flag:** `ROOT@KNU11{STRXX_L1GHtt_P4Y4LuG4}`

## Local run on Linux

```bash
cd starlight-ctf
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Endpoints

- `/` — STARLIGHT terminal
- `/robots.txt` — hints at internal documentation
- `/internal-docs` — token and endpoint notes
- `POST /api/login` — issues a cadet token
- `GET /api/profile` — displays decoded claims
- `GET /api/archive` — restricted archive

## Deploy with GitHub + Vercel

1. Create a GitHub repository named `starlight-ctf`.
2. From this folder, run:

```bash
git init
git add .
git commit -m "Build STARLIGHT beginner web CTF"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/starlight-ctf.git
git push -u origin main
```

3. In Vercel, import the `starlight-ctf` repository and deploy. The included `vercel.json` configures the Python function and routes.
4. After changing code, run `git add . && git commit -m "Update STARLIGHT challenge" && git push`; Vercel should redeploy automatically when Git integration is enabled.

## Organizer safety note

This app intentionally disables JWT signature validation on protected endpoints to create the challenge. It is deliberately insecure and must only be deployed as an isolated CTF exercise. Do not reuse its authentication code for real applications, accounts, or sensitive data.
