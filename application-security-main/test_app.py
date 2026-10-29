import unittest
import sqlite3
import os
import bcrypt
from app import app, init_db, DB_PATH, validate_registration_input

class AppSecTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        self.client = app.test_client()
        init_db()

    def test_01_input_validation(self):
        # Valid password & email
        valid, errors = validate_registration_input("testuser", "test@domain.com", "Password@123")
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

        # Invalid email
        valid, errors = validate_registration_input("testuser", "not-an-email", "Password@123")
        self.assertFalse(valid)
        self.assertTrue(any("valid email" in e for e in errors))

        # Weak password (no special char)
        valid, errors = validate_registration_input("testuser", "test@domain.com", "Password123")
        self.assertFalse(valid)
        self.assertTrue(any("special character" in e for e in errors))

        # Weak password (short)
        valid, errors = validate_registration_input("testuser", "test@domain.com", "P@1")
        self.assertFalse(valid)
        self.assertTrue(any("at least 8 characters" in e for e in errors))

    def test_02_default_accounts_and_bcrypt(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        admin = cur.fetchone()
        self.assertIsNotNone(admin)
        self.assertEqual(admin['role'], 'admin')
        self.assertTrue(bcrypt.checkpw(b"Admin@12345!", admin['password_hash'].encode('utf-8')))
        conn.close()

    def test_03_login_and_session(self):
        # Successful login
        resp = self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@12345!'
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome back, admin", resp.data)

        # Logout
        resp_logout = self.client.post('/logout', follow_redirects=True)
        self.assertIn(b"safely logged out", resp_logout.data)

    def test_04_rbac_enforcement(self):
        # Log in as normal user
        self.client.post('/login', data={
            'identifier': 'johndoe',
            'password': 'User@12345!'
        }, follow_redirects=True)

        # User attempts to access /admin
        resp_admin = self.client.get('/admin')
        # Expect 403 Forbidden
        self.assertEqual(resp_admin.status_code, 403)
        self.assertIn(b"403 Forbidden", resp_admin.data)
        self.assertIn(b"Security Violation Intercepted", resp_admin.data)

if __name__ == '__main__':
    unittest.main()
