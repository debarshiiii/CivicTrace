# CivicTrace

**A civic-issue reporting and accountability platform, created by Debarshi Patikar.**

Citizens report problems (potholes, garbage, water leaks, broken streetlights) with a photo. AI checks the photo and scores how risky it is. Officials validate and assign the job to a field worker. The worker submits proof of the repair, and an official verifies it. Every step is recorded in a permanent audit log.

Stack: FastAPI (Python) + PostgreSQL, plain HTML/Tailwind/JavaScript, Leaflet + OpenStreetMap map, Google Gemini for photo analysis.

---

## 1. Project layout

```
civictrace/
  README.md
  backend/
    requirements.txt
    create_admin.py          <- creates accounts (admin, workers, ...)
    .env                     <- YOUR secrets (never share or commit)
    .env.example             <- template for .env
    app/
      main.py                <- all API endpoints
      ai_service.py          <- Gemini photo analysis + hotspot scoring
      auth.py                <- passwords, tokens, login lockout
      config.py              <- settings read from .env
      models.py, schemas.py, database.py, audit_service.py
      routers/officials.py
  frontend/src/pages/
    home.html                <- public live map
    report.html              <- citizens report an issue
    track-report.html        <- citizens track a case
    about.html               <- about the project
    login.html               <- staff AND worker login
    municipalcommandcenter.html   <- official dashboard
    casedetails.html         <- one case: AI result, assign, review
    verifyresolution.html    <- accept / reject a repair
    evidencereview.html      <- alternative review page
    accountabilityauditlogs.html  <- audit log
    workerfield.html         <- field worker app
    vendor/leaflet.js, leaflet.css   <- map library (local copy)
```

---

## 2. First-time setup

You need: **Python 3.10+**, **PostgreSQL**, **VS Code** (with the *Live Server* extension).

### 2.1 Database
Open pgAdmin (or `psql`) and create an empty database named `civictrace`. Tables are created automatically when the backend starts.

### 2.2 Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Create the file `backend/.env` (copy `.env.example`):

```dotenv
DATABASE_URL=postgresql://postgres:YOUR_DB_PASSWORD@localhost:5432/civictrace
SECRET_KEY=PASTE_A_LONG_RANDOM_STRING
GEMINI_API_KEY=YOUR_GEMINI_KEY
GEMINI_MODEL=gemini-flash-latest
```

Make a strong `SECRET_KEY`:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Start the backend **from the `backend` folder**:

```powershell
uvicorn app.main:app --reload
```

It runs at http://127.0.0.1:8000 (interactive API docs at http://127.0.0.1:8000/docs). Leave this window open.

### 2.3 Frontend
In VS Code open the `frontend/src/pages` folder, right-click `home.html` and choose **Open with Live Server**. The site opens at something like `http://127.0.0.1:5500/home.html`. Always use Live Server rather than double-clicking the files.

> The pages talk to the backend at `http://127.0.0.1:8000/api`. This address is written near the top of each page's script (`API_BASE`). Change it there if you deploy somewhere else.

---

## 3. Creating accounts (admin, officials, workers)

Public sign-up is **closed**. Accounts are created from the `backend` folder with the virtual environment active:

```powershell
python create_admin.py admin@example.com "StrongPass123" "Your Name" admin
python create_admin.py official@example.com "StrongPass123" "Officer One" official
python create_admin.py worker1@example.com "StrongPass123" "Worker One" worker
python create_admin.py auditor@example.com "StrongPass123" "Auditor" auditor
```

Format: `python create_admin.py <email> <password> "<full name>" <role>`

| Role | Can do |
|---|---|
| `admin` | Everything an official can, plus creating accounts |
| `supervisor` | Same powers as an official |
| `official` | View all cases, validate or reject, assign workers, verify repairs, re-run AI |
| `auditor` | **Read-only**: view cases and the audit log |
| `worker` | Field app only: see assigned jobs, upload photos, submit repair claims |

Passwords need at least 8 characters. Running the command again for an existing email **resets its password and role**, which is also how you recover a forgotten admin password.

---

## 4. How to access each area

There are three kinds of users. **Everyone signs in on the same page: `login.html`.** The system sends you to the right place based on your role.

### Citizens (no login)
| Page | Address | Purpose |
|---|---|---|
| Map | `home.html` | See reported issues on the live map |
| Report | `report.html` | Report an issue (a private token like `CT-AB12-CD34` is created for you) |
| Track | `track-report.html` | Enter a case ID such as `CVT-KOL-123456` to follow progress |
| About | `about.html` | About the project |

### Government users (admin, supervisor, official, auditor)
1. Open `login.html` (the person icon in the top-right of the home page also leads there).
2. Enter your email and password and press **Sign In to Dashboard**.
3. You land on **`municipalcommandcenter.html`**, the command center.

From there:
- Click any case row (or **View**) to see details. **Open the full case page** for the AI assessment, evidence photos and actions.
- On the case page you can **Validate**, **Reject**, **Assign Worker**, **Mark In Progress**, **Run AI Analysis Again** and **Review & Verify** (when a repair is waiting).
- **Audit Logs** in the side menu opens `accountabilityauditlogs.html`.
- Auditors see everything but the action buttons are hidden.

### Admin
Admins use the same login and dashboard as officials, with the extra power of creating accounts. New accounts are made with `create_admin.py` (section 3), or by a signed-in admin through `POST /api/auth/register` in http://127.0.0.1:8000/docs (press **Authorize** and paste the admin's login token).

### Field workers
1. Create the worker account (section 3).
2. Open `login.html` and sign in with the worker's email and password.
3. You land on **`workerfield.html`**, the field app.
4. An official must first **assign** a case to this worker. It then appears in the worker's list.
5. The worker opens the job, uploads a before-photo and an **after-photo**, writes a note, and submits the **resolution claim**.

A worker cannot open the command center, and an official cannot use the worker app.

---

## 5. Try the whole flow (5-minute test)

1. Create an admin and a worker (section 3). Start the backend and open `home.html`.
2. **Citizen:** open `report.html`, choose a category, mark a location, upload a real photo and submit. Note the case ID, then check the AI result card.
3. **Official:** sign in at `login.html`. Open the case, press **Validate Issue**, choose the worker and press **Assign Worker**.
4. **Worker:** sign out, sign in as the worker. Open the job, upload an after-photo and submit the claim.
5. **Official:** sign in again, open the case and press **Review & Verify**. Compare the photos and accept.
6. **Citizen:** open `track-report.html` with the case ID. It shows *resolved*.
7. **Audit:** the official opens **Audit Logs** and sees every step.

---

## 6. How a case moves

```
received -> validated -> assigned -> in_progress -> resolution_claimed -> resolved
```

- An official can **reject** a report that is received or validated.
- Rejecting a repair sends the case back to `in_progress` for rework, and the worker can claim again.
- Statuses cannot be skipped. The server refuses any invalid jump.

---

## 7. AI risk scoring

- **Severity (0-100):** Gemini rates the visible danger in the photo.
- **Hotspot (0-100):** 15 points for every other open report of the same type within 300 m in the last 60 days (maximum 100).
- **Risk score = 65% severity + 35% hotspot.** 75+ critical, 50+ high, 25+ moderate, below that low.
- A photo that does not match the chosen category is **flagged for manual review**.
- If Gemini is unavailable the report is still saved with a default score, and an official can press **Run AI Analysis Again** on the case page.

Get a Gemini key at https://aistudio.google.com/apikey. `gemini-flash-latest` always points to the newest Flash model.

---

## 8. The map

`home.html` uses Leaflet from the local `vendor/` folder. Background tiles are fetched **by your backend** (`/api/map/tiles/...`), so a map provider key stays in `.env` and never reaches the browser. With no key it uses a free public map.

To use a keyed map provider, add to `backend/.env`:

```dotenv
MAP_API_KEY=your_provider_key
MAP_TILE_URL=https://<provider tile address>/{z}/{x}/{y}.png?key={key}
```

`{key}` is filled in on the server. Tiles are cached and limited per IP address.

---

## 9. Security features

- Closed registration; only an admin can create accounts.
- Argon2 password hashing, 8+ character minimum, temporary lockout after 5 wrong logins (15 minutes).
- Signed, expiring login tokens; roles are checked on the server for every action.
- Citizens cannot set their own case ID or risk score.
- Photos are verified by file contents (real JPEG/PNG/WebP), limited to 8 MB and renamed.
- Only the person who just created a report can attach photos to it (short-lived key).
- The case status flow is enforced; a case cannot be marked resolved without a verified repair.
- Each action and its audit record are saved together.
- Audit logs are visible to government users only.
- API keys live only in `backend/.env`.
- Page text is escaped to prevent script injection.

**Keep safe:** never share or commit `.env`. If a key is ever shown in a chat, screenshot or public place, delete it and create a new one.

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'app'` | Run `uvicorn` from the `backend` folder |
| `ModuleNotFoundError` | Activate the virtual environment, then `pip install -r requirements.txt` |
| Login says invalid credentials | Reset with `python create_admin.py ...` |
| "Too many failed attempts" | Wait 15 minutes or restart the backend |
| Pages show "Failed to fetch" | The backend is not running on port 8000 |
| Map is blank | Check `vendor/leaflet.js` exists, restart the backend, hard-refresh with Ctrl+Shift+R, press F12 and read the Console |
| AI says unavailable | Check `GEMINI_API_KEY` in `.env` and restart; an official can re-run the AI later |
| Photo rejected | It must be a real JPEG, PNG or WebP under 8 MB |
| 403 "case key expired" on a photo | Photos must be added within 30 minutes of creating the report |

---

## 11. Author

CivicTrace was created and built by **Debarshi Patikar**.