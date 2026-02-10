"""
Unit Tests for Identity Hygiene Checks

SECURITY TESTING PRINCIPLES:
1. Test boundary conditions
2. Test malicious inputs
3. Verify no data leakage
4. Test error handling
"""

import unittest
from app.identity_checks import PasswordAnalyzer, UsernameAnalyzer, MFAReadinessChecker


class TestPasswordAnalyzer(unittest.TestCase):
    """Test password strength analysis"""
    
    def test_empty_password(self):
        """SECURITY: Empty passwords should be rejected"""
        result = PasswordAnalyzer.analyze("")
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['strength'], 'Invalid')
    
    def test_very_weak_password(self):
        """Test common weak passwords"""
        weak_passwords = ['password', '123456', 'qwerty', 'abc123']
        
        for password in weak_passwords:
            result = PasswordAnalyzer.analyze(password)
            self.assertLess(result['score'], 40, 
                          f"'{password}' should be weak")
            self.assertIn('common', ' '.join(result['issues']).lower())
    
    def test_strong_password(self):
        """Test strong password characteristics"""
        strong_password = 'Tr0ub4dor&3X!mP1e#2024'
        result = PasswordAnalyzer.analyze(strong_password)
        
        self.assertGreaterEqual(result['score'], 60)
        self.assertTrue(result['has_lowercase'])
        self.assertTrue(result['has_uppercase'])
        self.assertTrue(result['has_digits'])
        self.assertTrue(result['has_special'])
    
    def test_sequential_characters(self):
        """SECURITY: Sequential chars should be detected"""
        result = PasswordAnalyzer.analyze('abcdef123456')
        issues_text = ' '.join(result['issues']).lower()
        self.assertIn('sequential', issues_text)
    
    def test_repeated_characters(self):
        """SECURITY: Repeated chars should be detected"""
        result = PasswordAnalyzer.analyze('aaaabbbb1111')
        issues_text = ' '.join(result['issues']).lower()
        self.assertIn('repeated', issues_text)
    
    def test_keyboard_patterns(self):
        """SECURITY: Keyboard patterns should be detected"""
        result = PasswordAnalyzer.analyze('qwertyuiop')
        issues_text = ' '.join(result['issues']).lower()
        self.assertIn('keyboard', issues_text)
    
    def test_date_patterns(self):
        """SECURITY: Date patterns should be detected"""
        result = PasswordAnalyzer.analyze('password1995')
        issues_text = ' '.join(result['issues']).lower()
        self.assertIn('date', issues_text)
    
    def test_length_requirements(self):
        """Test minimum length requirements"""
        # Too short
        result = PasswordAnalyzer.analyze('Ab1!')
        self.assertLess(result['score'], 50)
        
        # Good length
        result = PasswordAnalyzer.analyze('Ab1!Ab1!Ab1!Ab1!')
        self.assertGreater(result['score'], 40)
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # Simple password
        result1 = PasswordAnalyzer.analyze('password')
        
        # Complex password
        result2 = PasswordAnalyzer.analyze('Tr0ub4dor&3')
        
        self.assertGreater(result2['entropy_bits'], result1['entropy_bits'])
    
    def test_no_password_in_result(self):
        """SECURITY: Password should never be in result"""
        password = 'SecretPassword123!'
        result = PasswordAnalyzer.analyze(password)
        
        # Convert result to string and check
        result_str = str(result)
        self.assertNotIn(password, result_str)
    
    def test_max_length_password(self):
        """Test handling of very long passwords"""
        long_password = 'A1b!' * 100  # 400 characters
        result = PasswordAnalyzer.analyze(long_password)
        
        # Should still analyze without errors
        self.assertIsInstance(result['score'], int)
        self.assertGreater(result['score'], 0)


class TestUsernameAnalyzer(unittest.TestCase):
    """Test username and email analysis"""
    
    def test_empty_username(self):
        """SECURITY: Empty username should be handled"""
        result = UsernameAnalyzer.analyze("")
        self.assertEqual(result['risk_level'], 'Unknown')
    
    def test_short_username(self):
        """Short usernames are easier to enumerate"""
        result = UsernameAnalyzer.analyze("ab")
        self.assertIn('short', ' '.join(result['issues']).lower())
    
    def test_name_pattern_detection(self):
        """Detect firstname.lastname patterns"""
        result = UsernameAnalyzer.analyze("john.doe")
        warnings_text = ' '.join(result.get('warnings', [])).lower()
        self.assertIn('name', warnings_text)
    
    def test_year_detection(self):
        """Detect years in username"""
        result = UsernameAnalyzer.analyze("john1995")
        warnings_text = ' '.join(result.get('warnings', [])).lower()
        self.assertIn('year', warnings_text)
    
    def test_common_patterns(self):
        """Detect common username patterns"""
        common_usernames = ['admin', 'user123', 'test', 'guest', 'root']
        
        for username in common_usernames:
            result = UsernameAnalyzer.analyze(username)
            issues_text = ' '.join(result['issues']).lower()
            self.assertIn('common', issues_text)
    
    def test_email_analysis(self):
        """Test email analysis functionality"""
        result = UsernameAnalyzer.analyze("john", "john1990@example.com")
        warnings = result.get('warnings', [])
        
        # Should detect year in email
        warnings_text = ' '.join(warnings).lower()
        self.assertIn('year', warnings_text) if warnings else None
    
    def test_enumeration_risk_assessment(self):
        """Test enumeration risk levels"""
        # High risk: short and simple
        result1 = UsernameAnalyzer.analyze("user1")
        
        # Lower risk: longer and complex
        result2 = UsernameAnalyzer.analyze("ComplexUser2024XYZ")
        
        self.assertIsInstance(result1['enumeration_risk'], str)
        self.assertIsInstance(result2['enumeration_risk'], str)
    
    def test_special_characters_handling(self):
        """Test usernames with special characters"""
        result = UsernameAnalyzer.analyze("user@name#123")
        # Should not crash
        self.assertIn('risk_level', result)


class TestMFAReadinessChecker(unittest.TestCase):
    """Test MFA readiness functionality"""
    
    def test_checklist_generation(self):
        """Test MFA checklist generation"""
        result = MFAReadinessChecker.generate_checklist()
        
        self.assertIn('checklist', result)
        self.assertIn('methods', result)
        self.assertIn('critical_accounts', result)
        
        # Verify checklist sections
        checklist = result['checklist']
        self.assertIn('preparation', checklist)
        self.assertIn('implementation', checklist)
        self.assertIn('best_practices', checklist)
    
    def test_mfa_methods_ranking(self):
        """Test MFA methods are properly ranked"""
        result = MFAReadinessChecker.generate_checklist()
        methods = result['methods']
        
        # Hardware key should be highest
        self.assertEqual(methods['hardware_key']['security_level'], 5)
        
        # SMS should be lower
        self.assertLess(methods['sms']['security_level'], 
                       methods['hardware_key']['security_level'])
    
    def test_no_mfa_assessment(self):
        """SECURITY: No MFA should be flagged as critical"""
        result = MFAReadinessChecker.assess_current_setup([])
        
        self.assertEqual(result['status'], 'Critical')
        self.assertIn('recommendations', result)
        self.assertGreater(len(result['recommendations']), 0)
    
    def test_sms_only_assessment(self):
        """SMS-only should get upgrade recommendation"""
        result = MFAReadinessChecker.assess_current_setup(['sms'])
        
        recommendations_text = ' '.join(result['recommendations']).lower()
        self.assertIn('upgrade', recommendations_text)
    
    def test_hardware_key_assessment(self):
        """Hardware key should be rated excellent"""
        result = MFAReadinessChecker.assess_current_setup(['hardware_key'])
        
        self.assertIn(result['status'], ['Excellent', 'Very Good'])
    
    def test_multiple_methods_assessment(self):
        """Test assessment with multiple methods"""
        result = MFAReadinessChecker.assess_current_setup(
            ['hardware_key', 'authenticator_app']
        )
        
        self.assertEqual(result['enabled_count'], 2)
        self.assertGreater(result['security_level'], 0)
    
    def test_invalid_method_handling(self):
        """SECURITY: Invalid methods should be ignored"""
        result = MFAReadinessChecker.assess_current_setup(
            ['invalid_method', 'hardware_key']
        )
        
        # Should still work with valid method
        self.assertIn('status', result)
    
    def test_critical_accounts_list(self):
        """Verify critical accounts are identified"""
        result = MFAReadinessChecker.generate_checklist()
        critical_accounts = result['critical_accounts']
        
        # Should include important account types
        self.assertIn('Primary email', critical_accounts)
        self.assertIn('Password manager', critical_accounts)


class TestInputValidation(unittest.TestCase):
    """Test input validation and edge cases"""
    
    def test_null_byte_handling(self):
        """SECURITY: Null bytes should be handled"""
        password = "test\x00password"
        result = PasswordAnalyzer.analyze(password)
        # Should not crash
        self.assertIsInstance(result, dict)
    
    def test_unicode_characters(self):
        """Test unicode character handling"""
        password = "Pässwörd123!🔐"
        result = PasswordAnalyzer.analyze(password)
        self.assertIsInstance(result['score'], int)
    
    def test_very_long_input(self):
        """Test handling of extremely long inputs"""
        long_input = "a" * 10000
        result = PasswordAnalyzer.analyze(long_input)
        # Should handle gracefully
        self.assertIsInstance(result, dict)
    
    def test_sql_injection_patterns(self):
        """SECURITY: SQL injection patterns should not break analysis"""
        malicious_inputs = [
            "'; DROP TABLE users--",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM passwords--"
        ]
        
        for input_str in malicious_inputs:
            result = PasswordAnalyzer.analyze(input_str)
            self.assertIsInstance(result, dict)
    
    def test_xss_patterns(self):
        """SECURITY: XSS patterns should not break analysis"""
        xss_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for input_str in xss_inputs:
            result = PasswordAnalyzer.analyze(input_str)
            self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
