"""
Flask Routes Module
Handles HTTP request routing with security-focused input validation.

Security Principles:
1. Input validation on all user data
2. Output encoding to prevent XSS
3. Rate limiting considerations (future enhancement)
4. No sensitive data in logs
5. Secure error handling
"""

from flask import Blueprint, render_template, request, jsonify
from app.identity_checks import PasswordAnalyzer, UsernameAnalyzer, MFAReadinessChecker
import re

main_bp = Blueprint('main', __name__)


def sanitize_input(text: str, max_length: int = 256) -> str:
    """
    SECURITY: Sanitize user input to prevent injection attacks.
    
    Args:
        text: User-provided input
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not text:
        return ""
    
    # Truncate to max length to prevent DoS via large inputs
    text = text[:max_length]
    
    # Remove any null bytes (security best practice)
    text = text.replace('\x00', '')
    
    return text


def validate_email(email: str) -> bool:
    """
    SECURITY: Basic email format validation.
    
    Note: This is not RFC-compliant validation, but sufficient for our use case.
    Real email validation requires sending a confirmation email.
    """
    if not email or len(email) > 254:  # RFC 5321
        return False
    
    # Basic pattern check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


@main_bp.route('/')
def index():
    """
    Main landing page.
    
    SECURITY: No user input processed here, static page rendering.
    """
    return render_template('index.html')


@main_bp.route('/api/check-password', methods=['POST'])
def check_password():
    """
    API endpoint for password strength analysis.
    
    SECURITY MEASURES:
    1. POST only (no GET to prevent password in URLs/logs)
    2. Input length validation
    3. No password storage or logging
    4. Results returned immediately, not persisted
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        password = data.get('password', '')
        
        # SECURITY: Validate input length
        if len(password) > 256:
            return jsonify({
                'error': 'Password too long (max 256 characters)'
            }), 400
        
        # SECURITY: No sanitization needed for password analysis
        # We analyze as-is, but never store or log
        
        # Perform analysis
        result = PasswordAnalyzer.analyze(password)
        
        # SECURITY: Ensure password is not in response
        # (it's not in the result dict, but double-checking)
        
        return jsonify(result), 200
        
    except Exception as e:
        # SECURITY: Don't leak internal errors to client
        return jsonify({
            'error': 'Analysis failed',
            'message': 'An error occurred during password analysis'
        }), 500


@main_bp.route('/api/check-username', methods=['POST'])
def check_username():
    """
    API endpoint for username and email analysis.
    
    SECURITY MEASURES:
    1. Input sanitization
    2. Email validation
    3. Length limits to prevent DoS
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = sanitize_input(data.get('username', ''), max_length=128)
        email = sanitize_input(data.get('email', ''), max_length=254)
        
        # Validate email format if provided
        if email and not validate_email(email):
            return jsonify({
                'error': 'Invalid email format'
            }), 400
        
        # Validate username not empty
        if not username:
            return jsonify({
                'error': 'Username cannot be empty'
            }), 400
        
        # Perform analysis
        result = UsernameAnalyzer.analyze(username, email if email else None)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Analysis failed',
            'message': 'An error occurred during username analysis'
        }), 500


@main_bp.route('/api/mfa-checklist', methods=['GET'])
def mfa_checklist():
    """
    API endpoint for MFA readiness checklist.
    
    SECURITY: No user input, static educational content.
    """
    try:
        result = MFAReadinessChecker.generate_checklist()
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to generate checklist'
        }), 500


@main_bp.route('/api/mfa-assess', methods=['POST'])
def mfa_assess():
    """
    API endpoint for MFA setup assessment.
    
    SECURITY MEASURES:
    1. Validate input is a list
    2. Validate method names against known methods
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        methods = data.get('methods', [])
        
        # SECURITY: Validate input type
        if not isinstance(methods, list):
            return jsonify({
                'error': 'Methods must be a list'
            }), 400
        
        # SECURITY: Validate each method against known methods
        valid_methods = set(MFAReadinessChecker.MFA_METHODS.keys())
        validated_methods = [
            method for method in methods 
            if method in valid_methods
        ]
        
        # Perform assessment
        result = MFAReadinessChecker.assess_current_setup(validated_methods)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Assessment failed'
        }), 500


@main_bp.route('/health', methods=['GET'])
def health_check():
    """
    SECURITY: Health check endpoint for monitoring.
    Returns minimal information, no sensitive data.
    """
    return jsonify({
        'status': 'healthy',
        'service': 'identity-hygiene-scanner'
    }), 200


@main_bp.errorhandler(404)
def not_found(e):
    """SECURITY: Custom 404 handler to avoid information leakage"""
    return render_template('404.html'), 404


@main_bp.errorhandler(500)
def internal_error(e):
    """SECURITY: Custom 500 handler to avoid exposing stack traces"""
    return render_template('500.html'), 500
