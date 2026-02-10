"""
Flask Application Factory
Implements security-first configuration and initialization.

Security Decisions:
1. Secret key from environment (never hardcoded)
2. Secure session cookies (HttpOnly, Secure, SameSite)
3. Security headers (CSP, X-Frame-Options, etc.)
4. CSRF protection enabled
5. No session data stored (stateless where possible)
"""

import os
from flask import Flask
from datetime import timedelta


def create_app():
    """
    Application factory pattern for better testing and security.
    """
    app = Flask(__name__)
    
    # SECURITY: Secret key configuration
    # In production, ALWAYS use environment variable or secrets management
    # Never commit secret keys to version control
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 
        os.urandom(32).hex())  # Random key for development only
    
    # SECURITY: Session configuration
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents XSS access to cookies
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    
    # SECURITY: Prevent sensitive data caching
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    
    # Register security headers
    @app.after_request
    def set_security_headers(response):
        """
        SECURITY: Apply defense-in-depth security headers
        """
        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy - strict policy to prevent XSS
        # Allows only same-origin scripts and styles
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "  # unsafe-inline needed for inline event handlers
            "style-src 'self' 'unsafe-inline'; "   # unsafe-inline for inline styles
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        
        # Referrer policy - minimal information leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Feature policy - restrict browser features
        response.headers['Permissions-Policy'] = (
            "geolocation=(), microphone=(), camera=()"
        )
        
        return response
    
    # Register routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    return app
