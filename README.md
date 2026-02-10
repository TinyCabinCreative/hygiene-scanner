# 🔐 Identity Hygiene Scanner

A privacy-first, security-focused web application for evaluating password strength, username patterns, and MFA (Multi-Factor Authentication) readiness. All analysis happens locally with zero external API calls or data persistence.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Flask](https://img.shields.io/badge/flask-3.0.0-lightgrey)
![License](https://img.shields.io/badge/license-MIT-orange)

## 🎯 Purpose

This tool helps individuals and organizations evaluate their identity security posture by analyzing:
- **Password Strength**: Against breach patterns, common passwords, and cryptographic entropy
- **Username Security**: Enumeration risks and privacy concerns
- **MFA Readiness**: Implementation guidance and current setup assessment

**Key Principle**: Privacy by design - no data leaves your machine.

## ⚡ Features

### Password Strength Analyzer
- ✅ Comprehensive strength scoring (0-100)
- ✅ Detection of common passwords and patterns
- ✅ Keyboard pattern recognition (qwerty, asdfgh, etc.)
- ✅ Sequential character detection (abc, 123)
- ✅ Repeated pattern analysis
- ✅ Shannon entropy calculation
- ✅ Estimated crack time (based on modern GPU capabilities)
- ✅ Character diversity analysis

### Username & Email Analyzer
- ✅ Enumeration risk assessment
- ✅ Personal information leak detection
- ✅ Date/year pattern identification
- ✅ Common pattern warnings (admin, user123, etc.)
- ✅ Email format validation
- ✅ Privacy risk scoring

### MFA Readiness Checker
- ✅ MFA method security rankings
- ✅ Current setup assessment
- ✅ Implementation checklist
- ✅ Critical account identification
- ✅ Best practices guidance

## 🛡️ Security Architecture

### Security-First Design Decisions

#### 1. **No External Dependencies**
- All processing happens locally in Python/JavaScript
- No third-party APIs or cloud services
- No external CDNs (all assets served locally)

**Why?** Eliminates data exfiltration vectors and ensures user privacy.

#### 2. **Zero Data Persistence**
- No databases, no file storage
- All analysis is in-memory only
- Passwords never logged or saved

**Why?** Prevents data breaches and ensures compliance with privacy regulations.

#### 3. **Defense-in-Depth Security Headers**
```python
X-Frame-Options: DENY                    # Prevent clickjacking
X-Content-Type-Options: nosniff         # Prevent MIME sniffing
X-XSS-Protection: 1; mode=block         # Enable XSS protection
Content-Security-Policy: [strict]       # Prevent XSS attacks
Referrer-Policy: strict-origin          # Minimize info leakage
```

**Why?** Multiple layers of security reduce attack surface.

#### 4. **Input Validation & Sanitization**
- Length limits on all inputs (DoS prevention)
- Null byte removal
- Email format validation
- Type checking on all API inputs

**Why?** Prevents injection attacks and DoS vulnerabilities.

#### 5. **Secure Session Management**
```python
SESSION_COOKIE_HTTPONLY = True          # Prevent XSS cookie theft
SESSION_COOKIE_SAMESITE = 'Lax'         # CSRF protection
SESSION_COOKIE_SECURE = True (prod)     # HTTPS-only cookies
```

**Why?** Protects user sessions from common web attacks.

#### 6. **POST-Only Sensitive Endpoints**
- Password checks use POST (never GET)
- Prevents passwords in URL logs
- No sensitive data in browser history

**Why?** Passwords in URLs can leak through referrer headers, browser history, and server logs.

#### 7. **Constant-Time Operations (Where Applicable)**
- Designed to prevent timing attacks
- No early returns based on password content

**Why?** Timing attacks can reveal information about password validation.

### Threat Model

**Protected Against:**
- ✅ Cross-Site Scripting (XSS)
- ✅ SQL Injection (no database, but inputs sanitized)
- ✅ Cross-Site Request Forgery (CSRF)
- ✅ Clickjacking
- ✅ MIME Type Confusion
- ✅ Information Disclosure
- ✅ Denial of Service (input length limits)
- ✅ Timing Attacks (constant-time comparisons)

**Not Protected Against (By Design):**
- ❌ Network-level attacks (use HTTPS in production)
- ❌ Compromised host (runs on user's machine)
- ❌ Malicious browser extensions

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Safari, Edge)

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/identity-hygiene-scanner.git
cd identity-hygiene-scanner
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python run.py
```

### 5. Access the Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## 🖥️ Usage

### Password Strength Analysis
1. Navigate to the "Password Strength" tab
2. Enter a password to analyze
3. Click "Analyze Password"
4. Review the strength score, issues, and recommendations

![Password Analysis Screenshot Placeholder]

### Username Analysis
1. Navigate to the "Username Analysis" tab
2. Enter your username (email optional)
3. Click "Analyze Username"
4. Review enumeration risks and privacy concerns

![Username Analysis Screenshot Placeholder]

### MFA Readiness
1. Navigate to the "MFA Readiness" tab
2. Review MFA methods ranked by security
3. Select your current MFA methods
4. Click "Assess My Setup"
5. Follow the implementation checklist

![MFA Readiness Screenshot Placeholder]

## 🧪 Testing

### Run All Tests
```bash
python -m pytest tests/
```

### Run Specific Test Suite
```bash
# Unit tests
python -m pytest tests/test_identity_checks.py

# Integration tests
python -m pytest tests/test_routes.py
```

### Run with Coverage
```bash
python -m pytest --cov=app tests/
```

## 🏗️ Project Structure

```
identity-hygiene-scanner/
├── app/
│   ├── __init__.py              # Flask app factory with security config
│   ├── routes.py                # API endpoints with input validation
│   ├── identity_checks.py       # Core analysis logic
│   ├── templates/
│   │   ├── index.html          # Main application interface
│   │   ├── 404.html            # Custom 404 page
│   │   └── 500.html            # Custom 500 page
│   └── static/
│       ├── css/
│       │   └── style.css       # Modern, responsive styling
│       └── js/
│           └── app.js          # Frontend logic with XSS protection
├── tests/
│   ├── __init__.py
│   ├── test_identity_checks.py # Unit tests
│   └── test_routes.py          # Integration tests
├── requirements.txt             # Pinned dependencies
├── run.py                       # Application entry point
└── README.md                    # This file
```

## 🔒 Security Best Practices

### For Development
1. **Never commit secrets** to version control
2. **Use environment variables** for configuration
3. **Keep dependencies updated**: `pip list --outdated`
4. **Run security audits**: `pip-audit` or `safety check`

### For Production Deployment

⚠️ **CRITICAL: This is a development application. For production use:**

1. **Use HTTPS**
   ```python
   app.config['SESSION_COOKIE_SECURE'] = True
   ```

2. **Set Strong Secret Key**
   ```bash
   export SECRET_KEY=$(python -c 'import os; print(os.urandom(32).hex())')
   ```

3. **Use Production WSGI Server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8000 'app:create_app()'
   ```

4. **Enable Rate Limiting** (add to requirements.txt)
   ```bash
   pip install Flask-Limiter
   ```

5. **Use Reverse Proxy** (Nginx/Apache)
   - Terminate SSL
   - Rate limiting
   - DDoS protection

6. **Regular Security Audits**
   ```bash
   pip install pip-audit
   pip-audit
   ```

## 📊 Algorithm Details

### Password Strength Scoring

The scoring algorithm uses multiple weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Length | 30% | 8-12 chars (10pts), 12-16 (20pts), 16+ (30pts) |
| Character Diversity | 40% | Each type (lower, upper, digit, special) = 10pts |
| Pattern Detection | -30% | Penalties for common patterns, sequences, repetition |

**Entropy Calculation:**
```
Entropy = log₂(pool_size^length)

Where pool_size = sum of:
- 26 (lowercase a-z)
- 26 (uppercase A-Z)  
- 10 (digits 0-9)
- 32 (special characters)
```

**Crack Time Estimation:**
Assumes 10 billion bcrypt-equivalent hashes/second on modern GPU hardware.

### Username Enumeration Risk

Assessed based on:
1. **Length**: Shorter = easier to brute force
2. **Predictability**: Common patterns (user123, admin)
3. **Personal Info**: Names, dates, sequential numbers
4. **Complexity**: Character variety

### MFA Security Ranking

| Method | Security Level | Phishing Resistant? |
|--------|---------------|---------------------|
| Hardware Key (FIDO2) | 5/5 | ✅ Yes |
| Authenticator App (TOTP) | 4/5 | ❌ No |
| Push Notification | 3/5 | ❌ No (MFA fatigue) |
| SMS | 2/5 | ❌ No (SIM swap) |
| Email | 1/5 | ❌ No |

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Write tests** for new functionality
4. **Ensure all tests pass**: `python -m pytest`
5. **Follow security best practices**
6. **Commit with clear messages**: `git commit -m 'Add amazing feature'`
7. **Push to branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### Security Vulnerabilities

🔴 **Do not open public issues for security vulnerabilities.**

Please email security concerns privately to: [your-email@example.com]

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Password entropy calculations based on NIST SP 800-63B guidelines
- Common password lists sourced from breach analysis research (SecLists, Have I Been Pwned)
- MFA security rankings based on FIDO Alliance and Microsoft research
- Keyboard pattern detection inspired by zxcvbn algorithm

## 📚 References

- [NIST Password Guidelines (SP 800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Microsoft MFA Research](https://www.microsoft.com/en-us/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/)
- [FIDO Alliance Standards](https://fidoalliance.org/)

## 📧 Contact

For questions, suggestions, or collaboration:
- GitHub Issues: [Project Issues](https://github.com/yourusername/identity-hygiene-scanner/issues)
- Email: [your-email@example.com]

---

**⚠️ Disclaimer**: This tool is for educational and awareness purposes. It does not guarantee security. Always follow industry best practices and consult security professionals for production deployments.

**🔐 Privacy Statement**: This application processes all data locally. No information is transmitted to external servers, stored in databases, or logged to files. Your passwords and personal information never leave your machine.
