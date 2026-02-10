# 🚀 Production Deployment Guide

## ⚠️ Important Security Notice

**This application is designed for local/development use by default.**

For production deployment, you MUST implement additional security measures outlined in this guide.

## 🔐 Pre-Deployment Security Checklist

Before deploying to production, ensure:

- [ ] HTTPS/SSL certificate configured
- [ ] Strong secret key set via environment variable
- [ ] Debug mode disabled
- [ ] Production WSGI server configured (not Flask dev server)
- [ ] Reverse proxy configured (Nginx/Apache)
- [ ] Rate limiting implemented
- [ ] Security headers verified
- [ ] Firewall rules configured
- [ ] Regular backups scheduled (if modified to store data)
- [ ] Monitoring and logging configured
- [ ] Security audit completed

## 🌐 Deployment Options

### Option 1: Docker Deployment (Recommended)

**1. Create Dockerfile**

```dockerfile
FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application
COPY . .

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run with gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:create_app()"]
```

**2. Create docker-compose.yml**

```yaml
version: '3.8'

services:
  web:
    build: .
    container_name: identity-hygiene-scanner
    restart: unless-stopped
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - FLASK_ENV=production
    ports:
      - "127.0.0.1:8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - web
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

**3. Build and Run**

```bash
# Generate secret key
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f
```

### Option 2: Traditional Server Deployment

**1. Install on Ubuntu Server**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv nginx certbot python3-certbot-nginx -y

# Create application directory
sudo mkdir -p /var/www/identity-hygiene-scanner
cd /var/www/identity-hygiene-scanner

# Clone or copy your application
# ... (upload your files)

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt gunicorn

# Create systemd service
sudo nano /etc/systemd/system/identity-hygiene-scanner.service
```

**2. Create Systemd Service File**

```ini
[Unit]
Description=Identity Hygiene Scanner
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/identity-hygiene-scanner
Environment="PATH=/var/www/identity-hygiene-scanner/venv/bin"
Environment="SECRET_KEY=YOUR_SECRET_KEY_HERE"
Environment="FLASK_ENV=production"
ExecStart=/var/www/identity-hygiene-scanner/venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:8000 \
    --timeout 30 \
    --access-logfile /var/log/identity-hygiene-scanner/access.log \
    --error-logfile /var/log/identity-hygiene-scanner/error.log \
    'app:create_app()'

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**3. Configure Nginx Reverse Proxy**

```nginx
# /etc/nginx/sites-available/identity-hygiene-scanner

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
    limit_req zone=general burst=20 nodelay;

    # Request size limits
    client_max_body_size 1M;
    client_body_buffer_size 128k;

    # Logging
    access_log /var/log/nginx/identity-hygiene-scanner-access.log;
    error_log /var/log/nginx/identity-hygiene-scanner-error.log;

    # Static files
    location /static {
        alias /var/www/identity-hygiene-scanner/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # API endpoints with stricter rate limiting
    location /api {
        limit_req zone=api burst=10 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    # Main application
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
}
```

**4. Enable and Start Services**

```bash
# Create log directory
sudo mkdir -p /var/log/identity-hygiene-scanner
sudo chown www-data:www-data /var/log/identity-hygiene-scanner

# Enable nginx site
sudo ln -s /etc/nginx/sites-available/identity-hygiene-scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Enable and start application service
sudo systemctl enable identity-hygiene-scanner
sudo systemctl start identity-hygiene-scanner
sudo systemctl status identity-hygiene-scanner

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### Option 3: Cloud Platform Deployment

#### Heroku

```bash
# Create Procfile
echo "web: gunicorn -w 4 'app:create_app()'" > Procfile

# Create runtime.txt
echo "python-3.11.0" > runtime.txt

# Deploy
heroku create identity-hygiene-scanner
heroku config:set SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
git push heroku main
```

#### AWS Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p python-3.11 identity-hygiene-scanner

# Create environment
eb create production-env

# Set environment variables
eb setenv SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Deploy
eb deploy
```

## 🔒 Production Security Hardening

### 1. Environment Variables

Create `/var/www/identity-hygiene-scanner/.env`:

```bash
SECRET_KEY=your-secure-secret-key-here
FLASK_ENV=production
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PREFERRED_URL_SCHEME=https
```

### 2. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH
sudo ufw enable

# Fail2ban for brute force protection
sudo apt install fail2ban
```

### 3. Rate Limiting (Application Level)

Add to `requirements.txt`:
```
Flask-Limiter==3.5.0
```

Update `app/__init__.py`:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def create_app():
    app = Flask(__name__)
    
    # ... existing config ...
    
    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per hour"],
        storage_uri="memory://"
    )
    
    return app
```

### 4. Monitoring and Logging

**Set up Prometheus + Grafana**:

```python
# requirements.txt
prometheus-flask-exporter==0.22.4

# app/__init__.py
from prometheus_flask_exporter import PrometheusMetrics

def create_app():
    app = Flask(__name__)
    metrics = PrometheusMetrics(app)
    # ...
```

**Set up centralized logging**:

```python
import logging
from logging.handlers import RotatingFileHandler

def create_app():
    app = Flask(__name__)
    
    if not app.debug:
        file_handler = RotatingFileHandler(
            'logs/app.log',
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
```

## 📊 Health Monitoring

Add health check endpoint (already included):

```bash
# Monitor health
curl https://yourdomain.com/health

# Expected response:
{"status":"healthy","service":"identity-hygiene-scanner"}
```

## 🔄 Continuous Deployment

**GitHub Actions example** (`.github/workflows/deploy.yml`):

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python -m unittest discover tests

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to server
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.SERVER_HOST }}
          username: ${{ secrets.SERVER_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /var/www/identity-hygiene-scanner
            git pull
            source venv/bin/activate
            pip install -r requirements.txt
            sudo systemctl restart identity-hygiene-scanner
```

## 🧪 Pre-Production Testing

```bash
# Load testing with Apache Bench
ab -n 1000 -c 10 https://yourdomain.com/

# Security scan with OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://yourdomain.com

# SSL test
testssl.sh https://yourdomain.com

# Check security headers
curl -I https://yourdomain.com
```

## 📋 Maintenance Checklist

Weekly:
- [ ] Review application logs
- [ ] Check disk space
- [ ] Monitor response times

Monthly:
- [ ] Update dependencies (`pip list --outdated`)
- [ ] Review security advisories
- [ ] Check SSL certificate expiry
- [ ] Review access logs for anomalies

Quarterly:
- [ ] Security audit
- [ ] Performance optimization review
- [ ] Backup and restore test
- [ ] Update documentation

## 🆘 Troubleshooting

### Application won't start

```bash
# Check service status
sudo systemctl status identity-hygiene-scanner

# Check logs
sudo journalctl -u identity-hygiene-scanner -f

# Test gunicorn manually
cd /var/www/identity-hygiene-scanner
source venv/bin/activate
gunicorn -w 1 -b 127.0.0.1:8000 'app:create_app()'
```

### High memory usage

```bash
# Monitor processes
htop

# Reduce gunicorn workers in systemd file
# Change --workers 4 to --workers 2
```

### SSL certificate issues

```bash
# Renew certificate
sudo certbot renew

# Test auto-renewal
sudo certbot renew --dry-run
```

## 📞 Support

For production deployment support:
- Review [SECURITY.md](SECURITY.md)
- Check application logs
- Open a GitHub issue (non-security)
- Email: deployment-support@example.com

---

**Remember**: Production deployment requires ongoing maintenance and monitoring. Always follow security best practices!
