# Offline — Technical Documentation

Complete reference for `server.py` v1.0.0.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Configuration Reference](#2-configuration-reference)
3. [Database Schema](#3-database-schema)
4. [Authentication & Security](#4-authentication--security)
5. [Route Reference](#5-route-reference)
6. [File Server](#6-file-server)
7. [Microblog & Markdown](#7-microblog--markdown)
8. [Admin Dashboard](#8-admin-dashboard)
9. [Access Control (ACL)](#9-access-control-acl)
10. [Rate Limiting](#10-rate-limiting)
11. [TLS & HTTPS](#11-tls--https)
12. [Logging](#12-logging)
13. [Frontend & Theming](#13-frontend--theming)
14. [Code Structure](#14-code-structure)

---

## 1. Architecture

Offline is organized as a single Python file with clearly delimited sections. It uses only the Python standard library.

**Threading model:** Each incoming request is handled in its own thread (`socketserver.ThreadingMixIn`). Thread safety is maintained through:

- Per-request SQLite connections (sqlite3 handles this natively)
- `threading.Lock` around the global config dict
- `threading.Lock` around each rate-limit store

**Server topology:**

```
┌──────────────────────┐      ┌──────────────────────────┐
│  HTTP Server (:8080) │      │  HTTPS Server (:8443)    │
│  (info/redirect page)│      │  (main application)      │
│  ThreadedTCPServer   │      │  ThreadedTCPServer + SSL │
└──────────────────────┘      └──────────────────────────┘
         │                              │
         └──────────── main() ──────────┘
                    (2 daemon threads)
```

---

## 2. Configuration Reference

File: `data/config.json` — auto-created on first run, editable via `/admin/config`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `http_port` | int | `8080` | HTTP listener port |
| `https_port` | int | `8443` | HTTPS listener port |
| `host` | string | `"0.0.0.0"` | Bind address |
| `site_name` | string | `"Offline"` | Displayed in header and footer |
| `registration_open` | bool | `true` | Allow public user registration |
| `max_file_size_mb` | int | `100` | Maximum upload size in megabytes |
| `allowed_file_extensions` | list | `[]` | Allowed upload extensions; empty = all allowed |
| `token_expiry_seconds` | int | `86400` | Session token lifetime (default 24h) |
| `rate_limit_requests` | int | `60` | Max requests per IP per window |
| `rate_limit_window_seconds` | int | `60` | Rate limit window duration |
| `default_article_visibility` | string | `"public"` | Default visibility for new articles |

Config changes via the admin panel are applied immediately (no restart needed). The config dict is re-read on each request under a lock.

---

## 3. Database Schema

File: `data/db.sqlite3` — created with WAL journal mode and foreign keys enabled.

### users

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, autoincrement |
| `username` | TEXT | Unique, 3–32 chars `[a-zA-Z0-9_-]` |
| `password_hash` | TEXT | Base64-encoded PBKDF2-HMAC-SHA256 |
| `salt` | TEXT | 32-byte hex salt |
| `role` | TEXT | `superadmin`, `admin`, `mod`, or `user` |
| `group_name` | TEXT | Optional custom group assignment |
| `is_active` | INTEGER | 1 = active, 0 = deactivated |
| `created_at` | TEXT | ISO 8601 UTC timestamp |
| `last_login` | TEXT | ISO 8601 UTC timestamp |
| `pw_reset_notice` | INTEGER | 1 = show admin-reset warning on next login |

### tokens

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | FK → users.id |
| `token_hash` | TEXT | SHA-256 of the raw token (never store raw) |
| `created_at` | TEXT | ISO 8601 |
| `expires_at` | TEXT | ISO 8601 |
| `user_agent` | TEXT | Browser User-Agent string |
| `ip_address` | TEXT | Client IP at login |
| `revoked` | INTEGER | 1 = token invalidated |

### files

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key |
| `filename` | TEXT | Original user-provided filename |
| `stored_name` | TEXT | UUID-based name on disk (prevents path traversal) |
| `owner_id` | INTEGER | FK → users.id |
| `size_bytes` | INTEGER | File size |
| `mime_type` | TEXT | Detected MIME type |
| `visibility` | TEXT | `public`, `private`, `role:<name>`, `group:<name>` |
| `uploaded_at` | TEXT | ISO 8601 |
| `description` | TEXT | Optional user description |

### articles

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key |
| `title` | TEXT | Article title |
| `slug` | TEXT | Unique URL slug |
| `body` | TEXT | Raw Markdown source |
| `author_id` | INTEGER | FK → users.id |
| `visibility` | TEXT | Same visibility model as files |
| `created_at` | TEXT | ISO 8601 |
| `updated_at` | TEXT | ISO 8601 |
| `published` | INTEGER | 1 = published, 0 = draft |

### comments

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key |
| `article_id` | INTEGER | FK → articles.id (CASCADE delete) |
| `author_id` | INTEGER | FK → users.id (NULL for anonymous) |
| `author_name` | TEXT | Display name (for anonymous commenters) |
| `body` | TEXT | Comment text |
| `created_at` | TEXT | ISO 8601 |
| `approved` | INTEGER | 1 = visible, 0 = hidden/pending |

### groups

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key |
| `name` | TEXT | Unique group name |
| `description` | TEXT | Optional |
| `created_by` | INTEGER | FK → users.id |
| `created_at` | TEXT | ISO 8601 |

### group_members

| Column | Type | Notes |
|--------|------|-------|
| `group_id` | INTEGER | FK → groups.id (CASCADE) |
| `user_id` | INTEGER | FK → users.id (CASCADE) |
| | | Composite primary key |

### messages

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER | Primary key, autoincrement |
| `sender_id` | INTEGER | FK → users.id |
| `recipient_id` | INTEGER | FK → users.id |
| `subject` | TEXT | Max 200 characters |
| `body` | TEXT | Plain-text message body |
| `created_at` | TEXT | ISO 8601 |
| `read_at` | TEXT | NULL until read by recipient |
| `deleted_by_sender` | INTEGER | Soft-delete flag |
| `deleted_by_recipient` | INTEGER | Soft-delete flag |

---

## 4. Authentication & Security

### Password Storage

- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 310,000 (OWASP 2024 recommendation)
- **Salt:** 32-byte random hex (`secrets.token_hex(32)`)
- **Storage:** Base64-encoded hash + hex salt in separate columns

### Token Lifecycle

1. **Login** → generate `secrets.token_urlsafe(48)` raw token
2. **Store** SHA-256 hash of raw token in `tokens` table (raw token never stored)
3. **Send** raw token as `auth_token` cookie: `HttpOnly; Secure; SameSite=Strict`
4. **Validate** on each request: hash the cookie value, look up in DB, check expiry
5. **Also accepts** `Authorization: Bearer <token>` header for API use
6. **Revoke** on logout (single token) or "logout all devices" (all user tokens)

### CSRF Protection

Every state-changing form includes a hidden `csrf_token` field:

- Generated as: `timestamp.HMAC-SHA256(auth_token, timestamp)`
- Verified server-side with 4-hour maximum age
- Prevents cross-site form submission even if the auth cookie is present

### Password Validation Rules

- Minimum 12 characters
- Must contain at least one uppercase letter
- Must contain at least one lowercase letter
- Must contain at least one digit

### Security Headers

Set on every HTTPS response:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'
```

### SQL Injection Prevention

All database queries use parameterized `?` placeholders. No string formatting is used for SQL construction.

### XSS Prevention

All user content is escaped with `html.escape()` before rendering. The Markdown renderer HTML-escapes input before applying transformations.

### Path Traversal Prevention

Uploaded files are stored with server-generated names (`secrets.token_hex(16) + extension`). User-supplied filenames are never used for disk paths.

---

## 5. Route Reference

### Public Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | Any | Homepage — recent articles + files |
| GET | `/blog` | Any | Paginated article listing (20/page) |
| GET | `/blog/<slug>` | Visibility | Article detail + comments |
| POST | `/blog/<slug>/comment` | Any* | Post a comment |
| GET | `/files` | Any | Paginated file listing (20/page) |
| GET | `/files/<stored_name>` | ACL | Download file |
| GET | `/login` | Any | Login form |
| POST | `/login` | Any | Authenticate |
| GET | `/logout` | Logged-in | Revoke token, clear cookie |
| GET | `/register` | Any | Registration form (if open) |
| POST | `/register` | Any | Create account (if open) |

*Anonymous comments allowed on public articles (display name required).

### User Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/upload` | Logged-in | Upload form |
| POST | `/upload` | Logged-in | Handle file upload |
| GET | `/profile` | Logged-in | User profile + active sessions |
| POST | `/profile/logout-all` | Logged-in | Revoke all tokens |
| GET | `/profile/change-password` | Logged-in | Password change form |
| POST | `/profile/change-password` | Logged-in | Submit password change |

### Messaging Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/messages` | Logged-in | Inbox |
| GET | `/messages/sent` | Logged-in | Sent messages |
| GET | `/messages/compose` | Logged-in | Compose form (supports `?to=` and `?subject=`) |
| POST | `/messages/compose` | Logged-in | Send a message |
| GET | `/messages/<id>` | Logged-in | Read a message (marks as read) |
| POST | `/messages/<id>/delete` | Logged-in | Soft-delete a message |

### Utility Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/fingerprint` | Any | Display TLS certificate SHA-256 fingerprint |

### API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/preview` | Any | Render Markdown → HTML (for live preview) |

### Admin Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin` | mod+ | Dashboard with stats |
| GET | `/admin/users` | admin+ | User list |
| POST | `/admin/users/create` | admin+ | Create user |
| GET | `/admin/users/<id>/edit` | admin+ | Edit user form |
| POST | `/admin/users/<id>/edit` | admin+ | Save user changes |
| POST | `/admin/users/<id>/delete` | superadmin | Delete user |
| POST | `/admin/users/<id>/change-password` | admin+ | Force-reset password |
| GET | `/admin/files` | admin+ | File management |
| POST | `/admin/files/<id>/delete` | admin+ | Delete file |
| POST | `/admin/files/<id>/acl` | admin+ | Change file visibility |
| GET | `/admin/articles` | mod+ | Article management |
| GET | `/admin/articles/create` | mod+ | New article form |
| POST | `/admin/articles/create` | mod+ | Create article |
| GET | `/admin/articles/<id>/edit` | mod+/author | Edit article form |
| POST | `/admin/articles/<id>/edit` | mod+/author | Save article |
| POST | `/admin/articles/<id>/delete` | mod+ | Delete article |
| GET | `/admin/groups` | admin+ | Group management |
| POST | `/admin/groups/create` | admin+ | Create group |
| GET | `/admin/groups/<id>/members` | admin+ | Group member management |
| POST | `/admin/groups/<id>/members` | admin+ | Add/remove members |
| GET | `/admin/config` | superadmin | Site configuration |
| POST | `/admin/config` | superadmin | Save configuration |
| GET | `/admin/comments` | mod+ | Comment moderation |
| POST | `/admin/comments/<id>/approve` | mod+ | Approve comment |
| POST | `/admin/comments/<id>/delete` | mod+ | Delete comment |

---

## 6. File Server

### Upload Flow

1. User selects a file via the drag-drop zone or file picker
2. Client-side JavaScript sends the file with `XMLHttpRequest` (progress bar updates via `upload.onprogress`)
3. Server checks `Content-Length` against `max_file_size_mb`
4. Server validates file extension against `allowed_file_extensions` (if configured)
5. File is stored as `<random_hex>.<ext>` in `data/files/public/` or `data/files/private/`
6. Metadata is recorded in the `files` table

### Download Flow

1. Look up `stored_name` in database
2. Check visibility ACL against requesting user
3. Serve with correct `Content-Type`, `Content-Disposition: attachment`, and `Content-Length`
4. Stream in 64 KB chunks (avoids loading entire file into memory)

### Multipart Parser

The server includes a hand-written `multipart/form-data` parser (avoids the deprecated `cgi` module). It extracts fields and files based on the `boundary` from the `Content-Type` header.

---

## 7. Microblog & Markdown

### Markdown Renderer

The built-in `render_markdown()` function supports:

| Syntax | Output |
|--------|--------|
| `# Heading` through `######` | `<h1>` – `<h6>` |
| `**bold**` or `__bold__` | `<strong>` |
| `*italic*` or `_italic_` | `<em>` |
| `` `code` `` | `<code>` |
| ```` ``` ```` fenced blocks | `<pre><code>` |
| `> blockquote` | `<blockquote>` |
| `- item` or `* item` | `<ul><li>` |
| `1. item` | `<ol><li>` |
| `[text](url)` | `<a href="url">` |
| `![alt](url)` | `<img>` |
| `---` | `<hr>` |
| Blank line | Paragraph separator |

**XSS safety:** Input is HTML-escaped *before* Markdown transformation. Links get `rel="noopener noreferrer" target="_blank"`.

### Live Preview

The article editor includes a side-by-side preview panel. Client-side JavaScript posts to `/api/preview` (debounced 300ms) and renders the returned HTML.

### Comments

- Logged-in users: comment attributed to their account
- Anonymous users (public articles): prompted for a display name
- All comments auto-approved by default; mods can hide via `/admin/comments`
- Pending comment count shown as a badge in the admin sidebar

---

## 8. Admin Dashboard

### Dashboard (`/admin`)

- **Stats cards:** total users, files, articles, comments
- **Recent uploads:** last 10 files with uploader and date
- **Recent comments:** last 10 comments with author and preview
- **Recent logins:** last 5 users by login time

### User Management (`/admin/users`)

- Sortable, searchable table of all users
- Create new users with role assignment
- Edit role, group, active status
- Force-reset passwords with optional notification flag
- Delete users (superadmin only)

### Password Reset by Admin

- Admin cannot reset passwords for other admins or superadmin
- Superadmin can reset any account
- Optional "notify user" checkbox sets `pw_reset_notice` flag
- On next login, affected user sees: *"Your password was recently reset by an administrator"*
- Rate limited: 10 resets per hour per admin

### Config Panel (`/admin/config`)

Superadmin-only form that maps directly to `config.json` keys. Saves to disk and updates the in-memory config under a lock — no restart required.

---

## 9. Access Control (ACL)

The visibility system applies to both files and articles:

| Visibility | Who can access |
|-----------|---------------|
| `public` | Anyone, including anonymous visitors |
| `private` | Any logged-in user + admin/mod |
| `role:<name>` | Users with that exact role + admin/superadmin/mod |
| `group:<name>` | Members of the named group + admin/superadmin |

For article listings, inaccessible articles are silently excluded (no "forbidden" signal). For direct file/article access, a 403 error page is shown.

---

## 10. Rate Limiting

All rate limits use an in-memory sliding window, protected by `threading.Lock`.

| Scope | Limit | Window | Key |
|-------|-------|--------|-----|
| Global requests | 60 | 60 seconds | Client IP |
| Login failures | 10 | 5 minutes | Client IP |
| Password changes | 3 | 15 minutes | User ID |
| Admin password resets | 10 | 1 hour | Admin user ID |

When a rate limit is exceeded, the server returns **429 Too Many Requests** (global) or a redirect with an error flash message (endpoint-specific).

---

## 11. TLS & HTTPS

### Certificate Generation

On first run, if `data/certs/cert.pem` does not exist:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout data/certs/key.pem -out data/certs/cert.pem \
  -days 3650 -nodes -subj "/CN=localhost"
```

If `openssl` is not found, the server prints an error and exits.

### HTTP Redirect Page

The HTTP port does **not** perform a 301/302 redirect. Instead it serves a styled HTML page that:

- Explains the self-signed certificate
- Shows the SHA-256 fingerprint for verification
- Provides browser-specific trust instructions (Chrome, Firefox, Safari, iOS, Android)
- Links to the HTTPS URL

### Using Your Own Certificate

Replace `data/certs/cert.pem` and `data/certs/key.pem` with your own files. The server will use whatever certificate is present at those paths.

---

## 12. Logging

Two log files with rotating handlers (5 MB max, 3 backups):

### access.log

Every request:

```
2026-04-09 03:00:00,000 127.0.0.1 GET / 200
```

Special events:

```
2026-04-09 03:00:00,000 LOGIN user_id=1 ip=127.0.0.1
2026-04-09 03:00:00,000 REGISTER username=alice
2026-04-09 03:00:00,000 UPLOAD user_id=1 file=abc123.pdf size=102400
2026-04-09 03:00:00,000 PASSWORD_CHANGE user_id=2 by=self ip=127.0.0.1
2026-04-09 03:00:00,000 PASSWORD_CHANGE user_id=2 by=1 ip=127.0.0.1
```

### error.log

Python exceptions with full tracebacks (ERROR level). Never exposes stack traces to end users.

---

## 13. Frontend & Theming

### Design System

- **Font:** `system-ui, -apple-system, 'Segoe UI', sans-serif`
- **Accent color:** `#01696f` (light) / `#4f98a3` (dark)
- **Responsive:** CSS grid + flexbox, works from 375px to 1440px+
- **No external resources:** all CSS and JS are inline (no CDN calls)

### Dark/Light Mode

1. Defaults to OS preference via `prefers-color-scheme: dark`
2. Manual toggle button (🌓) in the header
3. Preference stored in `localStorage` — no server round-trip
4. Three states: `data-theme="light"`, `data-theme="dark"`, or unset (follows OS)

### UI Components

| Component | Implementation |
|-----------|---------------|
| Flash messages | Cookie-based, auto-dismiss after 4 seconds |
| File upload | Drag-drop zone + `XMLHttpRequest` progress bar |
| Markdown editor | Side-by-side textarea + live preview via `/api/preview` |
| Admin tables | Sortable by column click, searchable via filter input |
| Confirmation | Native `<dialog>` element for delete actions |
| Pagination | `?page=N` query parameter, 20 items per page |

---

## 14. Code Structure

The file is organized into 14 clearly commented sections:

| Section | Lines (approx.) | Contents |
|---------|--------|----------|
| 1. Imports & Constants | ~40 | All stdlib imports, version |
| 2. Configuration | ~70 | Config load/save, directory setup, logging |
| 3. Database | ~120 | Schema, init, helper functions |
| 4. Auth & Tokens | ~130 | Password hashing, tokens, CSRF, validation |
| 5. Rate Limiter | ~60 | In-memory sliding window limiters |
| 6. Markdown Renderer | ~80 | Regex-based MD→HTML conversion |
| 7. ACL & Permissions | ~40 | Visibility checks, role guards |
| 8. HTML Templates | ~350 | CSS, JS, base template, helper functions |
| 9. Request Handler & Router | ~150 | HTTP handler, routing, multipart parser |
| 10. Route Handlers | ~300 | Public pages (home, blog, files, auth) |
| 11. File Upload & Download | ~200 | Upload/download with ACL |
| 12. Admin Handlers | ~800 | All admin pages and actions |
| 13. TLS & Server Bootstrap | ~100 | Cert generation, HTTP redirect page, servers |
| 14. Startup & CLI | ~100 | Argument parsing, bootstrap sequence, main() |
