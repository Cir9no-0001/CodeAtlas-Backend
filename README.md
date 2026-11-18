# CodeAtlas Backend

Authentication backend prototype for [CodeAtlas](https://github.com/Cir9no-0001/CodeAtlas), a LeetCode-to-GitHub solution sync tool. Companion to the [CodeAtlas Chrome extension](https://github.com/Cir9no-0001/CodeAtlas-Extension).

> **Status: prototype, work in progress.** Not production-ready and not deployed. The extension does not call this backend yet; today it talks to GitHub directly. See [Known limitations](#known-limitations).

## How this was built

I wrote the application code (`app/`) by hand, on purpose. I'm using this project to learn how backends really work, and I didn't want a completely vibecoded backend I couldn't explain line by line.

AI tools were used to review/teach code. However, **the test suite is AI-generated**, as is this README for the most part (README will be completely hand written over once backend is complete).

## What's implemented

- **Email + password accounts** with signup, login and logout.
- **Password hashing** with Argon2 (via passlib). Logging in as an unknown user still runs a dummy hash verification, so response time doesn't reveal which emails are registered.
- **Server-side sessions**: random 256-bit tokens, 7-day expiry, delivered in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. An `Authorization: Bearer <token>` header is also accepted. Only a SHA-256 hash of each token is stored in the database, so a leaked database does not expose usable session tokens.
- **Password policy**: 10-128 characters. Passphrases of 16+ characters skip the complexity rules; shorter passwords need an uppercase letter, a lowercase letter, a digit and a special character.
- **Breached-password check** against the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API using k-anonymity (only the first 5 characters of the password's SHA-1 are sent). It fails open: if the API is unreachable, signup still works.
- **Rate limiting**: 5 requests per minute per client address on signup and login (slowapi).
- **GitHub and Google OAuth** via Authlib. An OAuth login is linked to an existing account only when the provider reports the email as verified. *Implemented but not yet covered by tests or verified end to end.*

## Tech stack

Python 3.12+, FastAPI, SQLAlchemy 2, PostgreSQL (psycopg 3), passlib (Argon2), Authlib, slowapi, pytest + httpx.

## Setup

```bash
git clone https://github.com/Cir9no-0001/CodeAtlas-Backend
cd CodeAtlas-Backend

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # then edit .env (see comments inside)
```

Start a local PostgreSQL (example using Docker; match the credentials in your `.env`):

```bash
docker run --name codeatlas-db \
  -e POSTGRES_USER=codeatlas -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=codeatlas \
  -p 5432:5432 -d postgres:16
```

Run the server:

```bash
uvicorn app.main:app --reload
```

Interactive API docs are at http://localhost:8000/docs. With `ENVIRONMENT=development` the tables are created automatically on startup. There are no migrations yet.

OAuth login needs a GitHub OAuth app and/or a Google OAuth client. The callback URLs are `<OAUTH_REDIRECT_BASE_URL>/auth/github/callback` and `<OAUTH_REDIRECT_BASE_URL>/auth/google/callback`.

## Running the tests

```bash
pytest
```

The test suite is AI-generated. It needs no `.env` and no database: it uses in-memory SQLite, the breached-password API is mocked, and the rate limiter is reset between tests. The tests cover signup, login, logout (including server-side session deletion), the password rules, the breach check (including the fail-open path), rate limiting, and that session tokens are stored only as hashes.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Health check |
| POST | `/auth/signup` | Create an account (email + password) |
| POST | `/auth/login` | Log in with email or username + password; sets the session cookie |
| POST | `/auth/logout` | Delete the session and clear the cookie |
| GET | `/auth/github/login` | Start GitHub OAuth |
| GET | `/auth/github/callback` | GitHub OAuth callback |
| GET | `/auth/google/login` | Start Google OAuth |
| GET | `/auth/google/callback` | Google OAuth callback |

## Known limitations

- No database migrations (Alembic). Tables are only auto-created in development.
- The rate limiter keeps counters in memory and keys on the connecting address, so it isn't suitable for multiple workers or for running behind a proxy without extra configuration.
- The OAuth flows are untested, and the handoff to the extension (session token in a URL fragment) is a placeholder.
- No protected endpoints yet. A `get_current_user` dependency exists but nothing uses it.
- No CORS configuration.
- Not hardened or deployed. Don't run it in production.

## Roadmap

- Wire the extension to this backend.
- Add a protected `/me` endpoint and use `get_current_user`.
- Add Alembic migrations.
- Add tests for the OAuth flows.

## License

Copyright (c) 2026 Stanley Chen. All rights reserved. The source is public for viewing and review only; no license is granted to copy, modify, or redistribute it.