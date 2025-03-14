
import unittest
import sqlite3
import os
from flask import Flask
from app import app
import database as db

class TestAppFunctions(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.test_database = "test_upskill_vision.db"
        app.config['DATABASE'] = cls.test_database
        app.config['TESTING'] = True
        cls.client = app.test_client()
    
        # Use app context for Flask operations
        with app.app_context():
            # Remove test database if it exists
            if os.path.exists(cls.test_database):
                os.remove(cls.test_database)
            
            cls._init_test_db()
    
    @classmethod
    def _init_test_db(cls):
        try:
            conn = sqlite3.connect(cls.test_database)
            cursor = conn.cursor()
        
            # Drop tables if they exist
            cursor.execute("DROP TABLE IF EXISTS course")
            cursor.execute("DROP TABLE IF EXISTS users")
        
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email text NOT NULL UNIQUE,
                    password TEXT,
                    role TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS course (
                    course_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NULL,
                    duration INTEGER NULL,
                    instructor_id INTEGER NOT NULL,
                    FOREIGN KEY (instructor_id) REFERENCES users(user_id)
                )''')        
            # Insert test data
            cursor.execute("INSERT INTO users (name, email, password, role) VALUES ('Harry', 'harry@gmail.com','harry@123','Instructor')")
            cursor.execute("INSERT INTO users (name, email, password, role) VALUES ('Sarah', 'sarah@gmail.com','sarah@123','Instructor')")
            cursor.execute("INSERT INTO users (name, email, password, role) VALUES ('John', 'john@gmail.com','john@123','User')")
            
            cursor.execute("INSERT INTO course (title, description, duration, instructor_id) VALUES ('Sales Force', 'Sales Force Fundamentals',3,2)")
            conn.commit()
        
        finally:
            conn.close()
              
    @classmethod
    def tearDownClass(cls):
        """Remove test database"""
        # Close any remaining connections
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.close()
    
        # Allow time for connections to fully close
        import time
        time.sleep(0.1)
    
        try:
            if os.path.exists(cls.test_database):
                os.remove(cls.test_database)
        except PermissionError:
            print("Warning: Could not remove test database - it may still be in use")
    
       
    # Test the routes
    def test_1index_route(self):
        """Test the index route"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
    
    def test_2add_course_route_get(self):
        """Test the GET method for add_course route"""
        response = self.client.get('/add_course')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Title', response.data)  # Check if the form is rendered
    
    def test_3add_course_route_post(self):
        """Test the POST method for add_course route"""
        instructor_id=301
        
        # Create form data
        form_data = {
            'title': 'Mobile App Development',
            'description': 'Learn to build mobile apps',
            'duration': 45,
            'mentor': instructor_id,
            'image' : 'a'
        }        
        # Submit form
        response = self.client.post('/add_course', data=form_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify the course was added
        self.assertIn(b'Mobile App Development', response.data)
    
    def test_4view_courses_route(self):
        """Test the view_courses route"""
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        
        # Verify some of our added courses are listed
        self.assertIn(b'Machine Learning', response.data)
        self.assertIn(b'Python Programming', response.data)
    
    def test_5edit_course_route(self):
        """Test the edit_course route"""
        course_id=1       
        
        # Test GET method
        response = self.client.get(f'/edit_course/{course_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sales Force Fundamentals', response.data)        
                
        # Test POST method
        form_data = {
            'title': 'Genai for Beginners',
            'description': 'Learn Genai Concepts',
            'duration': 6,
            'instructor_id': 2
        }
        
        response = self.client.post(f'/edit_course/{course_id}', data=form_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify the course was updated
        self.assertIn(b'enai for Beginners', response.data)
    
    
    def test_66delete_course_route(self):
        """Test the delete_course route"""
        course_id = 307  # Assume a course with ID 1 exists

        # Send a POST request to delete the course
        response = self.client.post(f'/deletedb/{course_id}', follow_redirects=True)

        # Check if the response status is 200 (successful redirect)
        self.assertEqual(response.status_code, 200)
        # Ensure the deleted course is no longer present in the course list
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'Salesforce', response.data) 

if __name__ == "__main__":
    unittest.main()