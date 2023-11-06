from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib
import os

app = Flask(__name__)
#app.secret_key = 'your_secret_key'

@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Connect to the SQLite database
        conn = sqlite3.connect('mydatabase.db')
        cursor = conn.cursor()

        # Create a table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                name TEXT,
                email TEXT,
                message TEXT
            )
        ''')

        # Insert data into the table
        cursor.execute('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)', (name, email, message))

        conn.commit()
        conn.close()

        return redirect(url_for('form'))
    
#login

def hash_password(password, salt):
    hash_obj = hashlib.sha256(salt.encode() + password.encode())
    return hash_obj.hexdigest()


@app.route('/register', methods=['POST'])
def register():
    #username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = 'user'  # Assign a default role, e.g., 'user'


    # Generate a random salt for each user (store it in the database)
    salt = os.urandom(16).hex()
    hashed_password = hash_password(password, salt)

    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    cursor.execute('INSERT INTO users ( email, password, role) VALUES (?, ?, ?)', ( email, hashed_password, role))
  
    conn.commit()
    conn.close()

    return redirect(url_for('login'))
###

if __name__ == '__main__':
    app.run(debug=True)
