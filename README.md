# Offline

A self-contained web platform in a single Python file. File server, microblog, user management, and admin dashboard, zero dependencies beyond the Python 3.10+ standard library.

## Features

- **Single file** — everything lives in `server.py`
- **No pip installs** — stdlib only (`http.server`, `sqlite3`, `ssl`, etc.)
- **Auto-bootstrap** — creates database, config, directories, TLS cert, and default admin on first run
- **Dual HTTP/HTTPS** — HTTP port serves a trust-instruction page; HTTPS serves the application
- **User auth** — PBKDF2-HMAC-SHA256 passwords, secure session tokens, role-based access control
- **File hosting** — upload, download, and manage files with visibility ACLs (public, private, group-restricted)
- **Microblog** — write articles in Markdown, comment system, visibility controls
- **Private messaging** — user-to-user mailbox with inbox, sent, compose, reply, and unread badges
- **Admin dashboard** — manage users, files, articles, groups, comments, and site configuration
- **Certificate verification** — fingerprint page accessible via footer link for self-signed cert trust
- **Responsive UI** — dark/light mode, mobile-friendly, inline CSS/JS (no CDN)

## Quick Start

```bash
python3 server.py
```

On first run the server will:

1. Create the `data/` directory structure
2. Generate a self-signed TLS certificate (requires `openssl` on PATH)
3. Create a default superadmin account and display credentials in a prominent banner — **save them immediately, they are only shown once**
4. Start listening on HTTP `:8080` and HTTPS `:8443`

Open `https://localhost:8443/` in your browser and log in with the printed credentials. Change the password right away via **Profile → Change Password**.

## Requirements

- Python 3.10, 3.11, 3.12, or 3.13
- `openssl` CLI (for TLS certificate generation)

## CLI Options

```
python3 server.py [options]

Options:
  --host HOST            Bind address (default: 0.0.0.0)
  --http-port PORT       HTTP port (default: 8080)
  --https-port PORT      HTTPS port (default: 8443)
  --data-dir PATH        Data directory (default: ./data)
  --create-user          Interactive prompt to create a new user
  --reset-password USER  Reset password for a username (prints new password)
  --version              Print version and exit
```

### Examples

```bash
# Custom ports
python3 server.py --http-port 80 --https-port 443

# Different data directory
python3 server.py --data-dir /var/myserver

# Create an admin user
python3 server.py --create-user

# Reset a forgotten password
python3 server.py --reset-password admin
```

## Data Layout

```
data/
├── db.sqlite3            SQLite database
├── config.json           Runtime configuration
├── certs/
│   ├── cert.pem          TLS certificate
│   └── key.pem           Private key
├── files/
│   ├── public/           Publicly accessible uploads
│   └── private/          Login-required uploads
└── logs/
    ├── access.log        Request log (rotating, 5 MB × 3)
    └── error.log         Error log (rotating, 5 MB × 3)
```

## Default Accounts

| Username | Role | Password |
|----------|------|----------|
| `admin` | superadmin | Random — printed to console on first run |

## Role Hierarchy

| Role | Permissions |
|------|------------|
| **superadmin** | Full access; site configuration; cannot be demoted via UI |
| **admin** | Manage users (except superadmin), files, articles, groups |
| **mod** | Moderate comments, edit/delete articles, manage files |
| **user** | Upload files, write articles, comment |
| **anonymous** | View public content only |

## Configuration

Edit `data/config.json` directly or use the admin panel at `/admin/config` (superadmin only). Changes apply immediately without restart.

See [DOC.md](DOC.md) for full configuration reference, API details, and security documentation.

## License

This project is provided as-is for personal and internal use.
