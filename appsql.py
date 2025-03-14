import sqlite3
from flask import Flask, render_template, redirect, url_for, request

app = Flask(__name__)
app.app_context().push()
db = sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db")
# Routes
@app.route('/')
def index():
    db = sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db")
    cursor=db.cursor()
    courses = cursor.execute("SELECT * FROM Course_demo").fetchall()
    print(courses)
    return render_template('index.html', courses=courses)

@app.route('/dashboard')
def dashboard():
    db = sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db")
    cursor=db.cursor()
    courses = cursor.execute("SELECT * FROM 'Course_demo'").fetchall()
    print(courses)
    return render_template('dashboard.html', courses=courses)
@app.route('/updatedb/<Course_ID>')
def updatedb(Course_ID):
    with sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db") as course:
        cursor=course.cursor()
        cursor.execute("Delete from 'Course_demo' where (CourseId)=?",(Course_ID,))
        return redirect(url_for('dashboard'))
@app.route('/deletedb/<Course_ID>')
def deletedb(Course_ID):
    with sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db") as course:
        cursor=course.cursor()
        print(Course_ID,cursor.execute("SELECT * FROM 'Course_demo'").fetchall())
        cursor.execute("Delete from 'Course_demo' where (CourseId)=?",(Course_ID,))
        return redirect(url_for('dashboard'))
@app.route('/add_course/<Course_ID>', methods=['GET', 'POST'])
def add_course(Course_ID):
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        action = request.form['action']
        print(action)
        if action == 'submit' or action == '':
            with sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db") as course:
                cursor=course.cursor()
                cursor.execute("INSERT INTO 'Course_demo' (title, description) VALUES (?, ?)", (title, description))
                course.commit()
            return redirect(url_for('dashboard'))
        else:
            with sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db") as course:
                cursor=course.cursor()
                cursor.execute("UPDATE 'Course_demo' set title=?, description=? where CourseID=?", (title, description,Course_ID))
                course.commit()
            return redirect(url_for('dashboard'))
    print(Course_ID)
    db = sqlite3.connect("C:\\Users\SAGNIK GHOSHAL\Downloads\DB.Browser.for.SQLite-v3.13.1-win64\\Course.db")
    cursor=db.cursor()
    courses = cursor.execute("SELECT * FROM 'Course_demo' where CourseID=?",(Course_ID,)).fetchall()
    print(courses)
    if courses!=[]:
        return render_template('add_course.html',course=courses)
    else:
        return render_template('add_course.html',course=[['','','','']])
if __name__ == '__main__':
    app.run(debug=True)
