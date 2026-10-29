# Project 4: Application Security Prototype

A defensive cybersecurity web application prototype built for college cybersecurity coursework, demonstrating foundational application security controls: **Authentication**, **Role-Based Access Control (RBAC)**, **Secure Password Storage (bcrypt)**, **Input Validation**, **Secure Session Management**, and **Defensive Audit Logging**.

---

## 1. Problem Statement

Web applications remain the primary attack vector in modern software ecosystems. Vulnerabilities such as broken authentication, broken access control (IDOR & privilege escalation), insecure password storage, and lack of input validation repeatedly rank among the **OWASP Top 10 Web Application Security Risks**. 

Without defense-in-depth measures:
- Attackers easily bypass authentication through credential stuffing and brute force.
- Normal authenticated users can escalate privileges to administrative endpoints due to missing authorization checks.
- Databases breached via SQLi or physical theft leak plaintext or weakly hashed passwords (e.g., MD5/SHA1).
- Malformed, malicious inputs corrupt state or trigger downstream injection attacks.

This project addresses these critical vulnerabilities by implementing a clean, hardened prototype illustrating how to mitigate them directly at the application and controller layers.

---

## 2. Objective

The primary objective of this prototype is to implement and demonstrate a secure web application architecture suitable for a **3-minute rapid cybersecurity demonstration**, featuring:
1. **Strong Authentication & Password Protection**: Enforcing salted, adaptive bcrypt hashing ($2b$12$) with client and server-side complexity policies.
2. **Strict Authorization & RBAC**: Differentiating standard `user` accounts from privileged `admin` accounts, preventing horizontal and vertical privilege escalation.
3. **Robust Input Validation**: Validating emails, usernames, and passwords with deterministic regex and sanity checks.
4. **Resilient Session Management**: Cryptographically signed cookie sessions with fixed lifetimes and secure invalidation upon logout.
5. **Real-Time Security Event Logging**: Tracking login attempts, registration, and unauthorized access violations for incident analysis.

---

## 3. Features

### A. Authentication & Session Management
- **User Registration**: Real-time password policy inspection and server-side validation.
- **User Login**: Multi-identifier login (supports both Username and Email) with constant-time verification.
- **Session Lifecycle**: Signed cookie sessions (`PERMANENT_SESSION_LIFETIME = 30m`) cleared on logout.
- **Demo Quick-Fill**: Single-click credentials autofill for rapid demonstration during oral evaluation.

### B. Secure Password Storage
- **Adaptive Hashing**: Uses `bcrypt` with automated per-user salting and 12 work factor rounds.
- **Timing Attack Mitigation**: Employs `bcrypt.checkpw` constant-time comparison to thwart timing-based enumeration.

### C. Role-Based Access Control (RBAC)
- **Role Hierarchies**: `user` (default) and `admin` (privileged).
- **Route Protection**: Custom Python decorators (`@login_required` and `@role_required(['admin'])`).
- **Custom 403 Forbidden Interception**: Informative security response page explaining access denial.

### D. Input Validation
- **Email Validation**: Strict RFC regex format validation.
- **Username Sanitization**: 3-25 alphanumeric and underscore characters.
- **Password Strength Rules**:
  - Minimum 8 characters
  - At least 1 uppercase letter (`A-Z`)
  - At least 1 lowercase letter (`a-z`)
  - At least 1 numeric digit (`0-9`)
  - At least 1 special character (`!@#$%^&*` etc.)
- **Duplicate Account Prevention**: Prevents collisions for existing usernames or email addresses.

### E. Security Demonstrations & Auditing
- **Simulate Privilege Escalation**: Built-in trigger on user dashboard for a regular user to attempt accessing `/admin`. Intercepts request, displays 403 Forbidden, and registers the attempt.
- **Security Audit Log Stream**: Admin SOC dashboard displays real-time logs of logins, authorization failures, and administrative role modifications.
- **User Management**: Admins can toggle privileges (promote/demote accounts) directly from the console.

---

## 4. Technologies Used

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | **Flask 3.1.x** (Python 3) | Lightweight WSGI web framework & routing |
| **Database** | **SQLite 3** | Zero-configuration ACID relational database |
| **Cryptography** | **bcrypt 5.0.x** | Adaptive, salted cryptographic password hashing |
| **Frontend Structure** | **HTML5 (Semantic)** | Accessible forms, cards, and data tables |
| **Frontend Styling** | **Vanilla CSS3** | Dark cybersecurity theme, glassmorphism, responsive |
| **Frontend Logic** | **Vanilla JavaScript (ES6)** | Dynamic password strength meter & quick-fill scripts |

---

## 5. Installation & Execution

### Prerequisites
- Python 3.9+ (or Python 3.14)
- `pip` package manager

### Step 1: Clone or Navigate to Project Directory
```bash
cd "c:\Cybersecurity\application security"
```

### Step 2: Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
py app.py
```

### Step 4: Access in Web Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 6. Default Demo Credentials

The application automatically initializes SQLite (`app_sec.db`) with two pre-seeded accounts:

| Role | Username | Email | Password | Access Rights |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin@cybersec.local` | `Admin@12345!` | Full access to `/dashboard` & `/admin` |
| **User** | `johndoe` | `john.doe@example.com` | `User@12345!` | Standard access to `/dashboard` only |

---

## 7. How It Works

### A. Authentication & Password Hashing Workflow
```
[User Input: Password] 
       │
       ▼
[validate_registration_input()] ──(Fails)──► [Flash Error Message to User]
       │ (Passes)
       ▼
[bcrypt.gensalt(12)] ──► Generates unique 128-bit cryptographically secure salt
       │
       ▼
[bcrypt.hashpw()] ──► Produces string: $2b$12$e8q... (cost + salt + hash)
       │
       ▼
[SQLite DB INSERT] ──► Plaintext password discarded from memory immediately
```

### B. Authorization (RBAC) Guard Workflow
```
[User requests /admin]
       │
       ▼
[@login_required] ──(Not logged in)──► Redirect to /login
       │ (Logged in)
       ▼
[@role_required(['admin'])]
       │
       ├──► If role == 'admin' ──► Render Admin SOC Dashboard
       │
       └──► If role != 'admin' 
                 │
                 ├──► Insert 'UNAUTHORIZED_ACCESS_ATTEMPT' into security_logs
                 └──► Abort 403 (Render custom 403 Forbidden page)
```

---

## 8. Security Considerations & Mitigations

1. **Password Cracking Resistance**: Using `bcrypt` with cost 12 makes brute-force attacks computationally expensive, resisting offline GPU/ASIC attacks far better than SHA-256 or MD5.
2. **Defeating Rainbow Tables**: Salting ensures that identical passwords yield completely distinct cryptographic hashes.
3. **Session Hijacking Mitigations**:
   - Cryptographically signed cookies prevent tampering with session keys.
   - 30-minute session timeout (`PERMANENT_SESSION_LIFETIME`).
   - Server-side session termination on logout.
4. **HTTP Security Headers**: Configured via `@app.after_request`:
   - `X-Frame-Options: DENY` (prevents Clickjacking)
   - `X-Content-Type-Options: nosniff` (MIME sniffing prevention)
   - `X-XSS-Protection: 1; mode=block` (Reflected XSS filter)
   - `Referrer-Policy: strict-origin-when-cross-origin`
5. **SQL Injection Defense**: All database queries use parameterized SQL statements (`?` placeholders), preventing user-supplied queries from altering query structure.

---

## 9. Future Improvements

While this prototype is intentionally designed to be lightweight, zero-dependency, and suitable for college presentations, production enterprise deployments would incorporate:
- **Multi-Factor Authentication (MFA/TOTP)**: Time-based one-time passwords via apps like Google Authenticator.
- **Account Lockout & Rate Limiting**: Exponential backoff or IP throttling via Redis/Flask-Limiter after consecutive failed login attempts.
- **Content Security Policy (CSP)**: Nonce-based CSP headers to completely neutralize inline script injections.
- **Automated Security Scanning**: Integration with DAST tools (OWASP ZAP) in a CI/CD pipeline.

---

## 10. Screenshots

### 1. Login Page with Demo Quick-Fill
![Login Page](screenshots/login_page.png)

### 2. Registration Page with Live Password Policy Meter
![Registration Page](screenshots/register_page.png)

### 3. User Dashboard with Privilege Escalation Demo Trigger
![User Dashboard](screenshots/user_dashboard.png)

### 4. Admin Security Operations Center (RBAC & Audit Logs)
![Admin Dashboard](screenshots/admin_dashboard.png)

### 5. Intercepted 403 Forbidden Privilege Escalation Attempt
![403 Forbidden](screenshots/forbidden_403.png)
#   a p p l i c a t i o n - s e c u r i t y  
 #   a p p l i c a t i o n - s e c u r i t y - m a i n  
 #   a p p l i c a t i o n - s e c u r i t y - m a i n  
 #   a p p l i c a t i o n - s e c u r i t y - m a i n  
 