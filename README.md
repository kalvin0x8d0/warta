# Warta — Private Micro-Blog Social Media

Private invite-only social platform for family & trusted friends.

<a href="http://creativecommons.org/publicdomain/zero/1.0/" title="CC0 1.0 Universal (CC0 1.0) Public Domain Dedication"><img src="https://licensebuttons.net/l/zero/1.0/80x15.png" width="80" height="15" alt="CC0 1.0 Universal (CC0 1.0) Public Domain Dedication"></a>

<a href="https://www.aihonestybadge.com" target="_blank" rel="noopener"><img src="https://www.aihonestybadge.com/badges/ai-generated.svg" alt="AI Generated Badge" style="max-width: 190px; height: auto;" /></a>

## Stack
- **Backend**: Go + pgx (PostgreSQL driver)
- **Database**: PostgreSQL 16
- **Frontend**: Vanilla HTML/CSS/JS (no build step needed)
- **Reverse proxy**: nginx container exposed on host port 50982
- **Deployment**: Docker Compose

---

## Setup

### 1. Prerequisites
- Docker + Docker Compose installed on your VPS

### 2. Configure environment
```bash
cp .env.example .env
nano .env
```
Fill in:
- `POSTGRES_PASSWORD` — strong random password
- `JWT_SECRET` — at least 32 random characters (use `openssl rand -hex 32`)
- `APP_BASE_URL` — your full domain, e.g. `https://warta.yourdomain.com`
- `ADMIN_EMAIL` — your email

### 3. Start
```bash
docker compose up -d
docker compose logs -f
```

The app will be accessible at `http://your-server:50982`.

### 4. First-time admin setup
Once running, create your admin account (one-time only):
```bash
curl -X POST https://yourdomain.com/api/setup \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "kalvin",
    "email": "you@email.com",
    "password": "your-strong-password",
    "display_name": "Kalvin"
  }'
```
After this, the `/api/setup` endpoint is permanently disabled.

### 5. Invite people
Log in at `https://yourdomain.com`, go to Invites, create an invite link, and share it with family/friends.

---

## Features

| Feature | Details |
|---|---|
| Microblog feed | Chronological, ≤280 chars |
| Long-form posts | Expandable from microblog card |
| Media | Images, audio (≤7 min), video (≤5 min) |
| Storage quota | 1024 MB per user |
| Dark/light mode | Auto (browser) + manual toggle |
| E2EE messaging | Web Crypto ECDH + AES-GCM, server never sees plaintext |
| Reactions | 👍 toggle |
| Comments | Threaded |
| Moderation | 2/3 community vote auto-removes · Admin can remove instantly |
| Invites | Any user can create, admin can revoke any |

## E2EE Notes

Messages use ECDH key agreement + AES-GCM encryption in the browser.
**Server stores only ciphertext — it cannot read messages.**

⚠️ If a user loses their device/clears their browser, their private key is gone and old messages cannot be decrypted. This is the honest trade-off of real E2EE.

To back up your key: `localStorage.getItem('e2ee_priv')` from browser console → save securely.

---

## Updating

```bash
git pull
docker compose build
docker compose up -d
```

## Backup

```bash
docker exec warta_db pg_dump -U warta warta > backup_$(date +%Y%m%d).sql
docker cp warta_backend:/app/uploads ./uploads_backup
```
