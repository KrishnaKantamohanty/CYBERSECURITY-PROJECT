# 🛡️ CYBERSECURITY SECURITY CENTER

A unified, interactive, defensive cybersecurity education and threat analysis platform built with Python and Streamlit.

---

## 1. Project Overview
The **Cybersecurity Security Center** transforms individual defensive security utilities into a unified security platform. It provides password evaluation, local credential vaulting, multi-factor authentication practice, authenticated file encryption, SHA-256 integrity digests, VirusTotal multi-engine malware analysis, URL phishing detection, automated IOC classification, central risk scoring, alert management, audit event logging, security report generation, and interactive lab exercises.

---

## 2. Features

- **Interactive Security Dashboard**: Real overall security score (0-100) calculated deterministically from active session controls and findings.
- **Identity & Passwords**: Real-time 5-tier password strength checker, cryptographically secure password generator (`secrets`), and encrypted local vault (`vault.db`).
- **Authentication & 2FA**: User registration, bcrypt password hashing, login verification, session timeout tracking, and TOTP Two-Factor Authentication (`pyotp`).
- **Encryption & Ciphers**: PBKDF2-HMAC-SHA256 key derivation + Fernet symmetric file encryption/decryption (`CYBERENCRv1` header) & interactive Caesar cipher demonstration.
- **Malware & File Security**: Local SHA-256 hash digests, VirusTotal API v3 multi-engine malware scanning, engine breakdown tables, and scan history.
- **Network & Web Security**: IP geolocation lookup (`ipinfo.io`), URL structure inspection, phishing heuristic analyzer, and automated IOC (Indicator of Compromise) classifier.
- **Security Center & Risk Engine**: Centralized severity classification (`INFO` to `CRITICAL`), alert manager with filter/review controls, safe security event audit logger, and MITRE ATT&CK TTP mapping.
- **Security Report Generator**: Executive report exporter in HTML, CSV, and printable PDF formats.
- **Interactive Security Lab**: Educational demonstrations covering password strength, hashing vs encryption, bcrypt salting, phishing red flags, and hash mismatch avalanche effects.
- **Application Security Health Check**: Automated self-diagnostic auditing key storage, encryption status, size limits, and deployment configuration.

---

## 3. Architecture

```text
cybersecurity_toolkit/
│
├── app.py                      # Main Streamlit Security Center entry point
├── requirements.txt            # Core Python dependencies
├── README.md                   # Complete documentation & ethical guide
├── .gitignore                  # Git exclusion rules for databases & keys
├── .env / secrets.toml         # Environment API key configuration
│
├── modules/
│   ├── password_tools.py       # Live strength checker & secure generator
│   ├── password_manager.py     # Local encrypted password vault
│   ├── authentication.py       # User sign-up, login & session management
│   ├── two_factor.py           # TOTP Two-Factor Authentication (pyotp)
│   ├── encryption_tools.py     # Authenticated file encryption & decryption
│   ├── file_integrity.py       # SHA-256 integrity & VirusTotal workflow
│   ├── virustotal_scanner.py   # VirusTotal API v3 client & parser
│   ├── network_tools.py        # IP geolocation & URL inspection
│   ├── phishing_detector.py    # Deceptive URL heuristic analyzer
│   ├── ioc_analyzer.py         # Automated IOC classifier (IP, Hash, URL, Email)
│   ├── risk_engine.py          # Central risk & overall security score engine
│   ├── alert_manager.py        # Security alert center & review queue
│   ├── security_events.py      # Safe audit event log manager
│   ├── report_generator.py     # Security report exporter (HTML, CSV, PDF)
│   ├── security_lab.py         # Interactive educational laboratory
│   └── security_health.py      # Application security self-assessment
│
├── utils/
│   ├── security.py             # Password evaluation, secrets generator, session stats
│   ├── hashing.py              # bcrypt password hashing & verification
│   ├── encryption.py           # PBKDF2HMAC + Fernet byte & file crypto routines
│   ├── vault.py                # SQLite database queries & key derivation
│   ├── validation.py           # Input regexes & URL validators
│   └── theme.py                # Custom CSS glassmorphism theme & UI badges
│
├── database/
│   └── vault.db                # SQLite database (master hash & encrypted vault entries)
│
└── data/
    ├── vault_salt.bin          # 16-byte random salt for master vault key derivation
    └── vault_key.bin           # Fernet-encrypted vault key payload
```

---

## 4. Technologies

- **Language**: Python 3.11+
- **Frontend / UI**: Streamlit 1.61+ with custom CSS styling
- **Database**: SQLite 3
- **Cryptography**: `cryptography` (PBKDF2HMAC, Fernet AES-128-CBC / HMAC-SHA256), `bcrypt`, `secrets`, `hashlib`
- **Authentication & 2FA**: `bcrypt`, `pyotp`
- **Networking & API**: `requests`, `urllib.parse`, `ipaddress`

---

## 5. Installation

1. Clone or download the repository:
   ```bash
   git clone <repository-url>
   cd "CYBERSECURITY PROJECT"
   ```

2. Create and activate a Python virtual environment:
   - Windows:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - macOS / Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 6. Configuration & VirusTotal API Setup

The multi-engine malware scanner connects to VirusTotal API v3.

1. Obtain a free VirusTotal API Key from [virustotal.com](https://www.virustotal.com).
2. Configure your API key via any of the following safe methods:
   - **Environment Variable**:
     ```bash
     export VIRUSTOTAL_API_KEY="your_api_key_here"
     ```
   - **Streamlit Secrets (`.streamlit/secrets.toml`)**:
     ```toml
     VIRUSTOTAL_API_KEY = "your_api_key_here"
     ```
   - **In-App Override**: Enter the key in **Settings** or directly in the **Malware Scan** tab for temporary session use.

> 🔒 **Security Guarantee**: API keys are kept in volatile memory or local configuration and are never logged, committed to version control, or rendered in reports.

---

## 7. Running the Application

Launch the Streamlit Security Center:
```bash
streamlit run app.py
```
Open your web browser at `http://localhost:8501`.

---

## 8. Database Architecture

The local vault uses SQLite (`database/vault.db`):
- `master` table: Stores `password_hash` (bcrypt digest of the master password).
- `vault_entries` table: Stores `service`, `username`, `password_blob` (Fernet-encrypted ciphertext), `notes`, `created_at`, `updated_at`.

Vault master key derivation uses PBKDF2HMAC SHA-256 with 260,000 iterations and a 16-byte random salt (`data/vault_salt.bin`), encrypting a randomly generated Fernet key saved in `data/vault_key.bin`.

---

## 9. Security Architecture

- **Zero Plaintext Credentials**: Plaintext passwords are never stored in files or database columns.
- **Authenticated Encryption**: File encryption appends an 11-byte signature header `CYBERENCRv1`, a 16-byte random salt, and Fernet ciphertext (AES-128-CBC + HMAC-SHA256).
- **Size Limits**: File uploads are strictly capped at 50 MB to mitigate Denial of Service (DoS).
- **Sanitized Logging**: The security event audit log redacts any string containing sensitive credential fields.

---

## 10. Threat Analysis & Scoring Methodology

The Overall Security Score (0-100) is calculated deterministically from active session security controls:
- **Baseline**: 80 Points
- **2FA Status**: +10 if active, -5 if disabled.
- **Password Evaluation**: +5 if strong password evaluated, -10 if weak password detected.
- **Malware Detections**: -15 points per high/critical malicious file scan detection.
- **Phishing URL Checks**: -10 points per high-risk phishing URL detected.
- **File Integrity Checks**: -10 points per SHA-256 hash mismatch.

---

## 11. Limitations & Privacy Considerations

- **Multi-Engine Scanning**: VirusTotal public API quotas apply. Not all engines analyze every file format.
- **No Absolute Safety**: A clean VirusTotal scan (0 detections) does **not** guarantee a file is free from zero-day threats.
- **Privacy Warning**: File hash lookups send SHA-256 digests to VirusTotal. File uploads transmit raw bytes to VirusTotal security vendors. Do not submit confidential or restricted files without authorization.
- **Educational Scope**: Designed as a local defensive education and assessment platform.

---

## 12. Testing

Run python compilation test across all modules:
```bash
python -c "import compileall; compileall.compile_dir('modules'); compileall.compile_dir('utils'); compileall.compile_file('app.py')"
```

---

## 13. Ethical & Legal Disclaimer

This software is strictly intended for **defensive cybersecurity education, learning, and local security assessment**. It does not perform unauthorized network scanning, exploitation, credential harvesting, malware execution, or attack vector deployment. Always obtain explicit authorization before submitting third-party artifacts or scanning external resources.
