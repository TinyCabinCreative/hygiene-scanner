# Security Policy

## 🔐 Security Philosophy

Identity Hygiene Scanner is built with a **security-first, privacy-first** approach. Every design decision prioritizes user data protection and follows the principle of "privacy by design."

## 🛡️ Security Features

### 1. Local-Only Processing
- **No external API calls**: All analysis happens locally in Python
- **No data transmission**: User inputs never leave the local machine
- **No cloud dependencies**: Zero reliance on external services

### 2. Zero Data Persistence
- **In-memory only**: All processing happens in RAM
- **No database**: No persistent storage of any kind
- **No logging**: Passwords and sensitive data never logged
- **Stateless design**: Each request is independent

### 3. Defense-in-Depth Headers

```python
X-Frame-Options: DENY
X-Content-Type-Options: nosniff  
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 4. Input Validation & Sanitization

**All user inputs are validated:**
- Maximum length enforcement (DoS prevention)
- Type checking (prevents injection)
- Null byte removal (security best practice)
- Email format validation
- Method whitelisting (MFA assessment)

### 5. Secure Session Management

```python
SESSION_COOKIE_HTTPONLY = True      # XSS protection
SESSION_COOKIE_SAMESITE = 'Lax'     # CSRF protection  
SESSION_COOKIE_SECURE = True        # HTTPS only (production)
PERMANENT_SESSION_LIFETIME = 30min  # Automatic expiry
```

### 6. API Security

**POST-only for sensitive endpoints:**
- Passwords use POST (never GET)
- Prevents URL logging of sensitive data
- No sensitive data in browser history

**Error handling:**
- Generic error messages (no info leakage)
- Stack traces hidden from users
- Proper HTTP status codes

## 🎯 Threat Model

### Protected Against

✅ **Cross-Site Scripting (XSS)**
- Content Security Policy
- Output encoding (textContent, not innerHTML)
- HTML entity escaping

✅ **SQL Injection**
- No database (by design)
- Input sanitization (defense in depth)

✅ **Cross-Site Request Forgery (CSRF)**
- SameSite cookies
- No state-changing GET requests

✅ **Clickjacking**
- X-Frame-Options: DENY

✅ **MIME Type Confusion**
- X-Content-Type-Options: nosniff

✅ **Information Disclosure**
- Generic error messages
- No stack traces in production
- Minimal server information headers

✅ **Denial of Service (Application Layer)**
- Input length limits
- Request size limits
- No expensive operations on untrusted input

✅ **Timing Attacks**
- Constant-time password validation (where applicable)
- No early returns based on sensitive data

### Not Protected Against (Scope Limitations)

❌ **Network-level attacks**
- **Mitigation**: Deploy behind HTTPS with proper certificates

❌ **Compromised host/browser**
- **Mitigation**: Users should secure their own machines

❌ **Physical access attacks**
- **Mitigation**: Out of scope for web application

❌ **Social engineering**
- **Mitigation**: User education (part of app's mission)

## 🚨 Reporting Security Vulnerabilities

**Please DO NOT open public GitHub issues for security vulnerabilities.**

### Responsible Disclosure

If you discover a security vulnerability:

1. **Email**: Send details to `security@example.com` (replace with actual email)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

3. **Expected Response Time**:
   - Initial response: 48 hours
   - Status update: 7 days
   - Fix timeline: Varies by severity

### Hall of Fame

We maintain a list of security researchers who responsibly disclosed vulnerabilities:

- (None yet - be the first!)

## 🔍 Security Audits

### Self-Audit Checklist

Before each release, we verify:

- [ ] All dependencies updated to latest stable versions
- [ ] `pip-audit` passes with no vulnerabilities
- [ ] All tests pass (unit + integration)
- [ ] Security headers verified in all responses
- [ ] Input validation on all endpoints
- [ ] No sensitive data in logs
- [ ] Error messages don't leak information
- [ ] CSP policy tested and working
- [ ] Rate limiting implemented (if applicable)
- [ ] HTTPS enforced in production

### Running Security Scans

```bash
# Check for known vulnerabilities in dependencies
pip install pip-audit
pip-audit

# Alternative: safety check
pip install safety
safety check

# Static analysis
pip install bandit
bandit -r app/

# Dependency license check
pip install pip-licenses
pip-licenses
```

## 🔐 Cryptographic Details

### Password Entropy Calculation

```
Entropy = log₂(pool_size^length)

Pool sizes:
- Lowercase: 26 characters
- Uppercase: 26 characters  
- Digits: 10 characters
- Special: ~32 characters (conservative estimate)
```

**Note**: This is an **estimation** for educational purposes. Real-world entropy may vary based on password generation method.

### Crack Time Estimation

**Assumptions**:
- Modern GPU: ~10 billion bcrypt-equivalent hashes/second
- Average case: 50% of keyspace searched
- Based on 2024 hardware capabilities

**Important**: These are rough estimates. Actual attack scenarios vary significantly.

## 🏭 Production Deployment Security

### Critical Production Settings

**1. HTTPS Only**
```python
# In production config
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'
```

**2. Strong Secret Key**
```bash
# Generate cryptographically secure key
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

**3. Production WSGI Server**
```bash
# Never use Flask development server in production!
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:8000 'app:create_app()'
```

**4. Reverse Proxy**
Use Nginx or Apache to:
- Terminate SSL/TLS
- Add rate limiting
- DDoS protection
- Request size limits

Example Nginx config:
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
    limit_req zone=one burst=20 nodelay;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**5. Environment Variables**
Never hardcode secrets:
```bash
# .env file (NEVER commit to git!)
SECRET_KEY=your-secret-key-here
FLASK_ENV=production
```

**6. Rate Limiting**
```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/check-password', methods=['POST'])
@limiter.limit("10 per minute")
def check_password():
    # ...
```

## 🧪 Security Testing

### Automated Testing

Run the test suite:
```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=app --cov-report=html

# Only security-focused tests
python -m pytest tests/ -k security
```

### Manual Security Testing Checklist

- [ ] Test with malicious inputs (SQL injection patterns)
- [ ] Test with XSS payloads
- [ ] Test with extremely long inputs
- [ ] Test with null bytes and special characters
- [ ] Test with malformed JSON
- [ ] Test concurrent requests
- [ ] Verify HTTPS redirect works
- [ ] Check security headers in all responses
- [ ] Test CSRF protection
- [ ] Verify no sensitive data in error messages

### Penetration Testing

For production deployments, consider:
- Professional penetration testing
- Bug bounty program
- Regular security audits
- Third-party code review

## 📋 Security Best Practices for Users

### For Developers Using This Tool

1. **Run locally**: Don't expose to public internet without proper hardening
2. **Use HTTPS**: Always in production environments
3. **Keep updated**: Regularly update dependencies
4. **Monitor logs**: Watch for unusual patterns
5. **Backup regularly**: Even though there's no database

### For End Users

1. **Use trusted instances**: Only use verified deployments
2. **Verify HTTPS**: Check for valid SSL certificate
3. **Don't paste real passwords**: Use test passwords when trying the tool
4. **Be aware**: No tool can guarantee 100% security

## 🔄 Security Update Process

1. **Vulnerability Discovered**: Via report or dependency scan
2. **Impact Assessment**: Severity rating (Critical/High/Medium/Low)
3. **Fix Development**: Patch created and tested
4. **Security Advisory**: Published if public disclosure needed
5. **Release**: Patched version deployed
6. **Notification**: Users notified via release notes

## 📚 Security Resources

### Standards & Guidelines
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Flask Security
- [Flask Security Considerations](https://flask.palletsprojects.com/en/latest/security/)
- [Flask-Security-Too](https://flask-security-too.readthedocs.io/)

### Password Security
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

## 📄 Security Compliance

This application follows:
- OWASP Secure Coding Practices
- NIST Password Guidelines (SP 800-63B)
- CWE/SANS Top 25 Most Dangerous Software Errors (mitigation)

## ✅ Security Certifications

While this is an open-source tool without formal certifications, the code follows security standards that align with:
- ISO/IEC 27001 principles
- OWASP ASVS (Application Security Verification Standard)
- CIS Controls

---

**Last Updated**: 2024
**Version**: 1.0.0

For questions about security, contact: security@example.com
