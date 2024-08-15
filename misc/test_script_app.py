import unittest
import os
import base64
from flask import url_for
from app_usingSYSINFOwithCustomAesKeyAndChunkwiseDynamickey import TestCase
from app_usingSYSINFOwithCustomAesKeyAndChunkwiseDynamickey import create_app, db
from app_usingSYSINFOwithCustomAesKeyAndChunkwiseDynamickey.models import User, Video

class FlaskAppTestCase(TestCase):

    def create_app(self):
        # Use a testing configuration for the app
        config_name = 'testing'
        app = create_app(config_name)
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app

    def setUp(self):
        db.create_all()
        # Create a test user
        self.user = User(username="testuser", email="testuser@example.com")
        self.user.set_password("password")
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_user_registration(self):
        """Test user registration."""
        response = self.client.post(url_for('auth.register'), data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpassword',
            'confirm_password': 'newpassword'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirection
        self.assertTrue(User.query.filter_by(username='newuser').first())

    def test_user_login(self):
        """Test user login."""
        response = self.client.post(url_for('auth.login'), data={
            'username': 'testuser',
            'password': 'password'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirection
        with self.client:
            response = self.client.get(url_for('main.index'))
            self.assertIn(b'Welcome, testuser!', response.data)

    def test_video_upload(self):
        """Test video upload and encryption."""
        self.client.post(url_for('auth.login'), data={
            'username': 'testuser',
            'password': 'password'
        })

        # Simulate video upload
        video_data = base64.b64encode(b"fake video data").decode('utf-8')
        response = self.client.post(url_for('upload_video'), data={
            'video_name': 'test_video.mp4',
            'video_data': video_data,
            'recipient': 'testuser2@example.com'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Video uploaded and encrypted successfully', response.data)
        self.assertTrue(Video.query.filter_by(name='test_video.mp4').first())

    def test_video_playback(self):
        """Test video decryption and playback."""
        self.client.post(url_for('auth.login'), data={
            'username': 'testuser',
            'password': 'password'
        })

        # Simulate video upload
        video_data = base64.b64encode(b"fake video data").decode('utf-8')
        self.client.post(url_for('upload_video'), data={
            'video_name': 'test_video.mp4',
            'video_data': video_data,
            'recipient': 'testuser@example.com'
        })

        # Simulate video playback
        response = self.client.get(url_for('play_video', video_id=1))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Video playback successful', response.data)

    def test_invalid_login(self):
        """Test login with invalid credentials."""
        response = self.client.post(url_for('auth.login'), data={
            'username': 'invaliduser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)

    def test_logout(self):
        """Test user logout."""
        self.client.post(url_for('auth.login'), data={
            'username': 'testuser',
            'password': 'password'
        })

        response = self.client.get(url_for('auth.logout'))
        self.assertEqual(response.status_code, 302)  # Check for redirection
        response = self.client.get(url_for('main.index'))
        self.assertNotIn(b'Welcome, testuser!', response.data)

if __name__ == '__main__':
    unittest.main()
