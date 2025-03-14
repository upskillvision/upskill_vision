import sqlite3
from flask import current_app

def get_db_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Create database tables if they don't exist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    # cursor.execute('''
    #             CREATE TABLE IF NOT EXISTS users (
    #                 user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    #                 name TEXT NOT NULL,
    #                 email text NOT NULL UNIQUE,
    #                 password TEXT,
    #                 role TEXT NOT NULL
    #             )
    #         ''')
    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS course (
    #         course_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    #         title TEXT NOT NULL,
    #         description TEXT NULL,
    #         duration INTEGER NULL,
    #         instructor_id INTEGER NOT NULL,
    #         FOREIGN KEY (instructor_id) REFERENCES users(user_id)
    #     )
    # ''')
    conn.commit()
    conn.close()

def get_instructors():
    """Get all instructors from the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, name FROM users WHERE role = 'Instructor'")
    instructors = cursor.fetchall()
    conn.close()
    return instructors

def add_course(title, description, duration, instructor_id):
    """Add a new course to the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO course (title, description, duration, instructor_id)
        VALUES (?, ?, ?, ?)
    ''', (title, description, duration, instructor_id))
    conn.commit()
    conn.close()

def get_courses():
    """Get all courses with instructor name"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT course.course_id, course.title, course.description, course.duration,
               users.name as instructor_name
        FROM course
        JOIN users ON course.instructor_id = users.user_id
    ''')
    courses = cursor.fetchall()
    conn.close()
    return courses

def get_course_by_id(course_id):
    """Get a course by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM course WHERE course_id = ?', (course_id,))
    course = cursor.fetchone()
    conn.close()
    return course

def update_course(course_id, title, description, duration, instructor_id):
    """Update an existing course"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE course
        SET title = ?, description = ?, duration = ?, instructor_id = ?
        WHERE course_id = ?
    ''', (title, description, duration, instructor_id, course_id))
    conn.commit()
    conn.close()

def delete_course_by_id(course_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM course WHERE course_id = ?', (course_id,))
        conn.commit()