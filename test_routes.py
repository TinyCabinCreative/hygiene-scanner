"""
Integration Tests for Flask Routes

SECURITY TESTING:
1. Test input validation
2. Test error handling
3. Test security headers
4. Test API responses
"""

import unittest
import json
from app import create_app


class TestFlaskRoutes(unittest.TestCase):
    """Test Flask application routes"""
    
    def setUp(self):
        """Set up test client"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_index_page(self):
        """Test main page loads"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Identity Hygiene Scanner', response.data)
    
    def test_security_headers(self):
        """SECURITY: Verify security headers are set"""
        response = self.client.get('/')
        
        # Check for security headers
        self.assertIn('X-Frame-Options', response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        
        self.assertIn('X-Content-Type-Options', response.headers)
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        
        self.assertIn('Content-Security-Policy', response.headers)
        self.assertIn('X-XSS-Protection', response.headers)
    
    def test_password_check_endpoint(self):
        """Test password checking endpoint"""
        response = self.client.post('/api/check-password',
            data=json.dumps({'password': 'TestPassword123!'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertIn('score', data)
        self.assertIn('strength', data)
        self.assertIn('issues', data)
        self.assertIn('recommendations', data)
    
    def test_password_check_empty(self):
        """SECURITY: Test empty password handling"""
        response = self.client.post('/api/check-password',
            data=json.dumps({'password': ''}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['score'], 0)
    
    def test_password_check_no_data(self):
        """SECURITY: Test missing data handling"""
        response = self.client.post('/api/check-password',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_password_check_too_long(self):
        """SECURITY: Test max length validation"""
        long_password = 'a' * 300
        response = self.client.post('/api/check-password',
            data=json.dumps({'password': long_password}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_username_check_endpoint(self):
        """Test username checking endpoint"""
        response = self.client.post('/api/check-username',
            data=json.dumps({
                'username': 'testuser',
                'email': 'test@example.com'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertIn('risk_level', data)
        self.assertIn('issues', data)
        self.assertIn('recommendations', data)
    
    def test_username_check_no_username(self):
        """SECURITY: Test empty username handling"""
        response = self.client.post('/api/check-username',
            data=json.dumps({'username': '', 'email': ''}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_username_check_invalid_email(self):
        """SECURITY: Test invalid email validation"""
        response = self.client.post('/api/check-username',
            data=json.dumps({
                'username': 'testuser',
                'email': 'not-an-email'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_mfa_checklist_endpoint(self):
        """Test MFA checklist endpoint"""
        response = self.client.get('/api/mfa-checklist')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertIn('checklist', data)
        self.assertIn('methods', data)
        self.assertIn('critical_accounts', data)
    
    def test_mfa_assess_endpoint(self):
        """Test MFA assessment endpoint"""
        response = self.client.post('/api/mfa-assess',
            data=json.dumps({'methods': ['hardware_key', 'authenticator_app']}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertIn('status', data)
        self.assertIn('recommendations', data)
    
    def test_mfa_assess_invalid_input(self):
        """SECURITY: Test invalid MFA method handling"""
        response = self.client.post('/api/mfa-assess',
            data=json.dumps({'methods': 'not-a-list'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertEqual(data['status'], 'healthy')
    
    def test_404_handling(self):
        """Test 404 error handling"""
        response = self.client.get('/nonexistent-page')
        self.assertEqual(response.status_code, 404)
    
    def test_method_not_allowed(self):
        """SECURITY: Test GET on POST-only endpoints"""
        response = self.client.get('/api/check-password')
        self.assertEqual(response.status_code, 405)
    
    def test_malformed_json(self):
        """SECURITY: Test malformed JSON handling"""
        response = self.client.post('/api/check-password',
            data='{"invalid json',
            content_type='application/json'
        )
        
        # Should handle gracefully
        self.assertIn(response.status_code, [400, 500])
    
    def test_sql_injection_in_username(self):
        """SECURITY: Test SQL injection patterns"""
        response = self.client.post('/api/check-username',
            data=json.dumps({
                'username': "admin'; DROP TABLE users--",
                'email': 'test@example.com'
            }),
            content_type='application/json'
        )
        
        # Should not crash, should sanitize
        self.assertEqual(response.status_code, 200)
    
    def test_xss_in_username(self):
        """SECURITY: Test XSS patterns"""
        response = self.client.post('/api/check-username',
            data=json.dumps({
                'username': "<script>alert('xss')</script>",
                'email': 'test@example.com'
            }),
            content_type='application/json'
        )
        
        # Should not crash, should sanitize
        self.assertEqual(response.status_code, 200)
    
    def test_content_type_validation(self):
        """SECURITY: Test content-type validation"""
        # Send form data instead of JSON
        response = self.client.post('/api/check-password',
            data='password=test',
            content_type='application/x-www-form-urlencoded'
        )
        
        # Should reject or handle gracefully
        self.assertIn(response.status_code, [400, 415, 500])


if __name__ == '__main__':
    unittest.main()
