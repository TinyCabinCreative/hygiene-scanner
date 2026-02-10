"""
Identity Hygiene Checks Module
Implements password strength analysis, username pattern detection, and MFA readiness checks.

Security Design Principles:
1. All processing is local (no external API calls)
2. No data persistence (privacy by design)
3. Pattern matching against known weak patterns
4. Educational feedback without storing sensitive data
5. Constant-time comparisons where applicable
"""

import re
import string
from typing import Dict, List, Tuple
from collections import Counter
import math


class PasswordAnalyzer:
    """
    Analyzes password strength using multiple security criteria.
    
    SECURITY NOTE: This class never stores passwords - all analysis is done
    in-memory and results are returned immediately.
    """
    
    # Common password patterns (sourced from breach analysis research)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football', 'welcome',
        'jesus', 'ninja', 'mustang', 'password1', 'admin',
        'administrator', 'root', 'toor', 'pass', 'test'
    }
    
    # Common substitution patterns (leetspeak)
    COMMON_SUBSTITUTIONS = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 
        'o': ['0'], 's': ['5', '$'], 't': ['7'], 'l': ['1']
    }
    
    # Keyboard patterns (adjacency attacks)
    KEYBOARD_PATTERNS = [
        'qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qwertyuiop',
        'asdfghjkl', 'zxcvbnm', '!qaz@wsx', '1q2w3e4r'
    ]
    
    @staticmethod
    def analyze(password: str) -> Dict:
        """
        Comprehensive password strength analysis.
        
        SECURITY: This method does not store the password. All analysis
        happens in-memory and the password should be cleared after use.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary with strength metrics and recommendations
        """
        if not password:
            return {
                'score': 0,
                'strength': 'Invalid',
                'issues': ['Password cannot be empty'],
                'recommendations': ['Enter a password to analyze'],
                'entropy_bits': 0,
                'crack_time': 'Instant'
            }
        
        issues = []
        recommendations = []
        score = 0
        
        # Length check (most important factor)
        length = len(password)
        if length < 8:
            issues.append('Password is too short (minimum 8 characters)')
            recommendations.append('Use at least 12-16 characters')
        elif length < 12:
            issues.append('Password could be longer for better security')
            score += 10
        elif length < 16:
            score += 20
        else:
            score += 30
        
        # Character diversity check
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        char_variety = sum([has_lower, has_upper, has_digit, has_special])
        
        if char_variety < 3:
            issues.append(f'Only uses {char_variety} character types')
            recommendations.append('Mix uppercase, lowercase, numbers, and symbols')
        else:
            score += char_variety * 10
        
        # Common password check
        if password.lower() in PasswordAnalyzer.COMMON_PASSWORDS:
            issues.append('This is a commonly used password (high breach risk)')
            recommendations.append('Use a unique, random password')
            score = max(0, score - 30)
        
        # Check for common passwords with simple modifications
        lower_pass = password.lower()
        for common in PasswordAnalyzer.COMMON_PASSWORDS:
            if common in lower_pass or lower_pass in common:
                issues.append('Contains a common password pattern')
                recommendations.append('Avoid dictionary words and common phrases')
                score = max(0, score - 20)
                break
        
        # Sequential character check
        if PasswordAnalyzer._has_sequential_chars(password):
            issues.append('Contains sequential characters (e.g., abc, 123)')
            recommendations.append('Avoid predictable sequences')
            score = max(0, score - 15)
        
        # Repeated character check
        if PasswordAnalyzer._has_repeated_chars(password):
            issues.append('Contains repeated character patterns')
            recommendations.append('Use more varied characters')
            score = max(0, score - 10)
        
        # Keyboard pattern check
        if PasswordAnalyzer._has_keyboard_pattern(password.lower()):
            issues.append('Contains keyboard pattern (e.g., qwerty)')
            recommendations.append('Avoid keyboard walking patterns')
            score = max(0, score - 15)
        
        # Personal information patterns
        if PasswordAnalyzer._has_date_pattern(password):
            issues.append('May contain date pattern (birthdays are easily guessed)')
            recommendations.append('Avoid dates, years, and personal information')
            score = max(0, score - 10)
        
        # Calculate entropy
        entropy = PasswordAnalyzer._calculate_entropy(password)
        
        # Estimate crack time
        crack_time = PasswordAnalyzer._estimate_crack_time(password, entropy)
        
        # Determine strength level
        if score < 20:
            strength = 'Very Weak'
        elif score < 40:
            strength = 'Weak'
        elif score < 60:
            strength = 'Fair'
        elif score < 80:
            strength = 'Good'
        else:
            strength = 'Strong'
        
        # Add positive feedback for strong passwords
        if score >= 80 and length >= 16:
            recommendations.append('✓ Excellent password strength!')
        
        return {
            'score': min(100, max(0, score)),
            'strength': strength,
            'length': length,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_special': has_special,
            'issues': issues if issues else ['No major issues detected'],
            'recommendations': recommendations if recommendations else [
                'Consider using a password manager for even stronger passwords'
            ],
            'entropy_bits': round(entropy, 2),
            'crack_time': crack_time
        }
    
    @staticmethod
    def _has_sequential_chars(password: str, min_length: int = 3) -> bool:
        """Check for sequential characters (abc, 123, etc.)"""
        for i in range(len(password) - min_length + 1):
            substr = password[i:i + min_length]
            # Check if ASCII values are sequential
            if all(ord(substr[j+1]) - ord(substr[j]) == 1 for j in range(len(substr)-1)):
                return True
            # Check reverse sequential
            if all(ord(substr[j]) - ord(substr[j+1]) == 1 for j in range(len(substr)-1)):
                return True
        return False
    
    @staticmethod
    def _has_repeated_chars(password: str, threshold: int = 3) -> bool:
        """Check for repeated characters (aaa, 111, etc.)"""
        for i in range(len(password) - threshold + 1):
            if len(set(password[i:i + threshold])) == 1:
                return True
        return False
    
    @staticmethod
    def _has_keyboard_pattern(password: str) -> bool:
        """Check for keyboard walking patterns"""
        for pattern in PasswordAnalyzer.KEYBOARD_PATTERNS:
            if pattern in password or pattern[::-1] in password:
                return True
        return False
    
    @staticmethod
    def _has_date_pattern(password: str) -> bool:
        """Check for date-like patterns (years, months, days)"""
        # Look for 4-digit years (1900-2099)
        if re.search(r'(19|20)\d{2}', password):
            return True
        # Look for MM/DD or DD/MM patterns
        if re.search(r'\d{1,2}[/-]\d{1,2}', password):
            return True
        return False
    
    @staticmethod
    def _calculate_entropy(password: str) -> float:
        """
        Calculate Shannon entropy of the password.
        
        SECURITY NOTE: Higher entropy indicates more randomness and unpredictability.
        Aim for at least 50-60 bits for strong passwords.
        """
        # Calculate character pool size
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'\d', password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += 32  # Approximate special characters
        
        # Entropy = log2(pool_size^length)
        if pool_size > 0:
            entropy = len(password) * math.log2(pool_size)
        else:
            entropy = 0
        
        return entropy
    
    @staticmethod
    def _estimate_crack_time(password: str, entropy: float) -> str:
        """
        Estimate time to crack using modern hardware.
        
        ASSUMPTIONS:
        - Modern GPU can try ~10 billion hashes/second (bcrypt-equivalent)
        - This is a rough estimate for educational purposes
        """
        # Handle very large entropy values to prevent overflow
        if entropy > 1000:
            return 'Millions of years (excellent!)'
        
        # Calculate possible combinations
        try:
            combinations = 2 ** entropy
        except OverflowError:
            return 'Millions of years (excellent!)'
        
        # Assume 10 billion attempts per second
        attempts_per_second = 10_000_000_000
        
        seconds = combinations / (2 * attempts_per_second)  # Average case
        
        if seconds < 1:
            return 'Less than 1 second'
        elif seconds < 60:
            return f'{int(seconds)} seconds'
        elif seconds < 3600:
            return f'{int(seconds / 60)} minutes'
        elif seconds < 86400:
            return f'{int(seconds / 3600)} hours'
        elif seconds < 31536000:
            return f'{int(seconds / 86400)} days'
        elif seconds < 31536000 * 100:
            return f'{int(seconds / 31536000)} years'
        elif seconds < 31536000 * 1000:
            return f'{int(seconds / 31536000)} years (centuries)'
        else:
            return 'Millions of years (excellent!)'


class UsernameAnalyzer:
    """
    Analyzes usernames for enumeration risks and privacy concerns.
    
    SECURITY CONTEXT: Username enumeration allows attackers to:
    1. Build lists of valid accounts for targeted attacks
    2. Correlate identities across platforms
    3. Perform social engineering attacks
    """
    
    @staticmethod
    def analyze(username: str, email: str = None) -> Dict:
        """
        Analyze username and email for security and privacy risks.
        
        Args:
            username: The username to analyze
            email: Optional email address to analyze
            
        Returns:
            Dictionary with risk assessment and recommendations
        """
        issues = []
        recommendations = []
        warnings = []
        
        if not username:
            return {
                'risk_level': 'Unknown',
                'issues': ['No username provided'],
                'recommendations': [],
                'warnings': []
            }
        
        # Length check
        if len(username) < 3:
            issues.append('Username is very short and may be easily guessed')
            recommendations.append('Use longer usernames (6+ characters) when possible')
        
        # Personal information detection
        if UsernameAnalyzer._contains_name_pattern(username):
            warnings.append('Username may contain personal name')
            recommendations.append('Consider using pseudonymous usernames for privacy')
        
        # Year/date detection
        if re.search(r'(19|20)\d{2}', username):
            warnings.append('Username contains year (may reveal birth year)')
            recommendations.append('Avoid including birth years in usernames')
        
        # Sequential numbers
        if re.search(r'\d{3,}', username):
            issues.append('Contains sequential numbers (easier to enumerate)')
            recommendations.append('Use random characters instead of sequential numbers')
        
        # Common username patterns
        common_patterns = ['admin', 'user', 'test', 'guest', 'root', 'demo']
        if any(pattern in username.lower() for pattern in common_patterns):
            issues.append('Uses common/default username pattern')
            recommendations.append('Avoid generic usernames like "admin" or "user123"')
        
        # Email analysis
        email_risks = []
        if email:
            email_risks = UsernameAnalyzer._analyze_email(email)
            if email_risks:
                warnings.extend(email_risks)
        
        # Determine risk level
        total_issues = len(issues) + len(warnings)
        if total_issues == 0:
            risk_level = 'Low'
        elif total_issues <= 2:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
        
        return {
            'risk_level': risk_level,
            'issues': issues if issues else ['No critical issues detected'],
            'recommendations': recommendations if recommendations else [
                'Username appears relatively secure'
            ],
            'warnings': warnings,
            'enumeration_risk': UsernameAnalyzer._assess_enumeration_risk(username)
        }
    
    @staticmethod
    def _contains_name_pattern(username: str) -> bool:
        """Detect if username might contain a real name"""
        # Look for firstname.lastname or firstname_lastname patterns
        if re.search(r'[a-z]+[._-][a-z]+', username.lower()):
            return True
        return False
    
    @staticmethod
    def _analyze_email(email: str) -> List[str]:
        """Analyze email address for privacy and security concerns"""
        risks = []
        
        # Check for disposable email domains (common ones)
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email'
        ]
        
        email_lower = email.lower()
        if any(domain in email_lower for domain in disposable_domains):
            risks.append('Using disposable email (may limit account recovery)')
        
        # Check for personal info in email
        if re.search(r'(19|20)\d{2}', email):
            risks.append('Email contains year/date')
        
        # Check for common free providers (not necessarily bad, but note for awareness)
        major_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
        if not any(provider in email_lower for provider in major_providers):
            # Might be custom domain - good for privacy
            pass
        
        return risks
    
    @staticmethod
    def _assess_enumeration_risk(username: str) -> str:
        """
        Assess how easily this username could be enumerated.
        
        SECURITY NOTE: Enumeration allows attackers to discover valid usernames
        through login attempt responses, password reset forms, or registration pages.
        """
        risk_factors = 0
        
        # Short usernames are easier to brute force
        if len(username) < 6:
            risk_factors += 1
        
        # Simple patterns increase risk
        if re.search(r'^[a-z]+\d+$', username.lower()):  # name123 pattern
            risk_factors += 1
        
        # All lowercase or all numbers
        if username.islower() or username.isdigit():
            risk_factors += 1
        
        if risk_factors == 0:
            return 'Low - username has good complexity'
        elif risk_factors <= 2:
            return 'Medium - consider adding complexity'
        else:
            return 'High - username is highly predictable'


class MFAReadinessChecker:
    """
    Evaluates Multi-Factor Authentication readiness and provides guidance.
    
    SECURITY CONTEXT: MFA is one of the most effective security controls.
    According to Microsoft, MFA blocks 99.9% of automated attacks.
    """
    
    # MFA method rankings by security strength
    MFA_METHODS = {
        'hardware_key': {
            'name': 'Hardware Security Key (FIDO2/U2F)',
            'security_level': 5,
            'description': 'Physical key like YubiKey - most secure option',
            'pros': ['Phishing-resistant', 'No phone required', 'Very secure'],
            'cons': ['Costs money', 'Can be lost', 'Needs backup method']
        },
        'authenticator_app': {
            'name': 'Authenticator App (TOTP)',
            'security_level': 4,
            'description': 'Apps like Google Authenticator, Authy, or Microsoft Authenticator',
            'pros': ['Works offline', 'More secure than SMS', 'Free'],
            'cons': ['Requires smartphone', 'Can be lost if phone is lost']
        },
        'push_notification': {
            'name': 'Push Notification',
            'security_level': 3,
            'description': 'Approve login from another device',
            'pros': ['Convenient', 'User-friendly'],
            'cons': ['Requires internet', 'Vulnerable to MFA fatigue attacks']
        },
        'sms': {
            'name': 'SMS Text Message',
            'security_level': 2,
            'description': 'Code sent via text message',
            'pros': ['Widely supported', 'Easy to use'],
            'cons': ['SIM swapping risk', 'Interception possible', 'Least secure']
        },
        'email': {
            'name': 'Email Verification',
            'security_level': 1,
            'description': 'Code sent to email',
            'pros': ['Universal availability'],
            'cons': ['If email is compromised, MFA is bypassed', 'Not true MFA']
        }
    }
    
    @staticmethod
    def generate_checklist() -> Dict:
        """
        Generate comprehensive MFA readiness checklist.
        
        Returns:
            Dictionary with checklist items and guidance
        """
        checklist = {
            'preparation': [
                {
                    'item': 'Identify all accounts that support MFA',
                    'priority': 'High',
                    'details': 'Start with email, banking, and social media'
                },
                {
                    'item': 'Choose your MFA method',
                    'priority': 'High',
                    'details': 'Hardware key > Authenticator app > SMS'
                },
                {
                    'item': 'Get necessary hardware/apps',
                    'priority': 'High',
                    'details': 'Purchase security keys or install authenticator app'
                }
            ],
            'implementation': [
                {
                    'item': 'Enable MFA on primary email account first',
                    'priority': 'Critical',
                    'details': 'Email is the recovery method for other accounts'
                },
                {
                    'item': 'Save backup/recovery codes',
                    'priority': 'Critical',
                    'details': 'Store in password manager or safe location'
                },
                {
                    'item': 'Register multiple MFA devices',
                    'priority': 'High',
                    'details': 'Prevent lockout if primary device is lost'
                },
                {
                    'item': 'Enable MFA on financial accounts',
                    'priority': 'Critical',
                    'details': 'Banks, payment apps, investment accounts'
                },
                {
                    'item': 'Enable MFA on social media',
                    'priority': 'Medium',
                    'details': 'Prevent account takeover and impersonation'
                },
                {
                    'item': 'Enable MFA on work/cloud accounts',
                    'priority': 'High',
                    'details': 'Google Workspace, Microsoft 365, AWS, etc.'
                }
            ],
            'best_practices': [
                {
                    'item': 'Never share MFA codes',
                    'priority': 'Critical',
                    'details': 'Legitimate services never ask for MFA codes'
                },
                {
                    'item': 'Be wary of MFA fatigue attacks',
                    'priority': 'High',
                    'details': 'Don\'t approve push notifications you didn\'t initiate'
                },
                {
                    'item': 'Review active sessions regularly',
                    'priority': 'Medium',
                    'details': 'Log out unknown devices'
                },
                {
                    'item': 'Keep backup codes secure',
                    'priority': 'High',
                    'details': 'Treat them like passwords'
                }
            ]
        }
        
        return {
            'checklist': checklist,
            'methods': MFAReadinessChecker.MFA_METHODS,
            'critical_accounts': [
                'Primary email',
                'Password manager',
                'Banking/financial',
                'Health records',
                'Government services'
            ]
        }
    
    @staticmethod
    def assess_current_setup(enabled_methods: List[str]) -> Dict:
        """
        Assess the security of current MFA setup.
        
        Args:
            enabled_methods: List of MFA methods currently enabled
            
        Returns:
            Assessment with recommendations
        """
        if not enabled_methods:
            return {
                'status': 'Critical',
                'message': 'No MFA enabled - account is vulnerable',
                'recommendations': [
                    'Enable MFA immediately on critical accounts',
                    'Start with authenticator app or hardware key',
                    'Save recovery codes in a secure location'
                ]
            }
        
        # Calculate security score
        max_level = max(
            MFAReadinessChecker.MFA_METHODS.get(method, {}).get('security_level', 0)
            for method in enabled_methods
        )
        
        recommendations = []
        
        if 'sms' in enabled_methods and max_level <= 2:
            recommendations.append(
                'Upgrade from SMS to authenticator app or hardware key'
            )
        
        if 'hardware_key' not in enabled_methods:
            recommendations.append(
                'Consider adding hardware security key for maximum protection'
            )
        
        if len(enabled_methods) < 2:
            recommendations.append(
                'Register backup MFA method to prevent lockout'
            )
        
        status_map = {
            1: 'Poor',
            2: 'Fair',
            3: 'Good',
            4: 'Very Good',
            5: 'Excellent'
        }
        
        return {
            'status': status_map.get(max_level, 'Unknown'),
            'security_level': max_level,
            'enabled_count': len(enabled_methods),
            'recommendations': recommendations if recommendations else [
                'MFA setup looks good! Keep recovery codes safe.'
            ]
        }
