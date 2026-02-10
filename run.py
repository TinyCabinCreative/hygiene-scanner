"""
Identity Hygiene Scanner - Main Entry Point
A security-focused tool for evaluating password strength, username patterns, and MFA readiness.

Security Principles Applied:
- No external API calls (data privacy)
- All processing happens locally
- No password storage or logging
- Secure headers configured
- Input validation at all layers
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    # Development server settings
    # SECURITY NOTE: Never use debug=True in production
    # SECURITY NOTE: Always use HTTPS in production with proper certificates
    app.run(
        host='127.0.0.1',  # Localhost only - prevents external network exposure
        port=5000,
        debug=True,  # Only for development
        threaded=True
    )
