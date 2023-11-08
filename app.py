from flask import Flask, render_template, request, redirect, url_for, session,flash

import sqlite3
import hashlib
import os
import bcrypt
import re


app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/contact')
def contact():
    # Check if the user is logged in using the session
    if 'user_username' in session:
        email = session['user_username']

        # Render the dashboard with user-specific data
        return render_template('contact.html', email=email)
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/protected')
def protected():
    # Check if the user is logged in using the session
    if 'user_username' in session:
        email = session['user_username']

        # Render the dashboard with user-specific data
        return render_template('protected.html', email=email)
    else:
        return redirect(url_for('login'))

@app.route('/protected_home')
def protected_home():
    # Check if the user is logged in using the session
    if 'user_username' in session:
        email = session['user_username']

        # Render the dashboard with user-specific data
        return render_template('protected_home.html', email=email)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    return redirect(url_for('login'))

#---------FORM--------------------------
# SQLite database setup
conn = sqlite3.connect('user_database.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS personal_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        zip_code TEXT,
        annual_income INTEGER,
        dependents INTEGER,
        gender TEXT
    )
''')
conn.commit()
conn.close()

@app.route('/submit', methods=['POST'])
def submit():
    zip_code = request.form['zip_code']
    annual_income = int(request.form['annual_income'])
    dependents = int(request.form['dependents'])
    gender = request.form['gender']

    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO personal_info (zip_code, annual_income, dependents, gender)
        VALUES (?, ?, ?, ?)
    ''', (zip_code, annual_income, dependents, gender))
    conn.commit()
    conn.close()

    #return redirect(url_for('protected'))
    email = session['user_username']
    return render_template('submission_confirmation.html', email=email)



#---------------------------------------
#-----PASSWORD POLICY RULES-------------
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL_CHAR = True
#--------------FUNCTIONS--------------

def hash_password(password, salt):
    # Generate a salted hash of the password
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
   # hashed_password = bcrypt.hashpw(salted_password, bcrypt.gensalt())
    hashed_password = bcrypt.hashpw(salted_password, salt.encode('utf-8'))

    # Return the hashed password as a bytes object
    return hashed_password


def generate_salt():
    return bcrypt.gensalt().decode('utf-8')

def is_valid_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False

    if REQUIRE_UPPERCASE and not any(char.isupper() for char in password):
        return False

    if REQUIRE_LOWERCASE and not any(char.islower() for char in password):
        return False

    if REQUIRE_DIGIT and not any(char.isdigit() for char in password):
        return False

    if REQUIRE_SPECIAL_CHAR and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True


#----------LOGIN------------------

@app.route('/userlogin', methods=['POST'])
def userlogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Perform user authentication here
        if user_is_authenticated(email, password):

            # Create a session for the user
            session['user_username'] = email
            
            return redirect(url_for('protected'))  # Redirect to a protected page

        # Handle unsuccessful login (e.g., show an error message)
        else:
            # Authentication failed, show an error message using flash
            flash('Incorrect username or password. Please try again.', 'error')
            return redirect(url_for('login'))  # Redirect back to the login form


def user_is_authenticated(email, password):
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    # Check if the email exists in the database
    cursor.execute('SELECT email, password, salt FROM users WHERE email = ?', (email,))

    user_data = cursor.fetchone()
    print("user_data",user_data)
    conn.close()

    if user_data is not None:
        stored_password = user_data[1]
        salt = user_data[2]
        
        if password is not None and salt is not None:
            # Hash the provided password with the stored salt
            hashed_password = hash_password(password,salt)
        
             # Compare the hashed passwords
            if hashed_password == stored_password:
                return True  # Authentication successful

    return False  # Authentication failed
#---------------------------------

#-------Registration--------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password-confirm']
        role = 'user'  # Assign a default role, e.g., 'user'
      
        if password != password_confirm:
            error = "Passwords do not match."

        if not is_valid_password(password):
            flash('Password does not meet the password policy requirements.', 'error')
       
        else:
            # Generate a new salt
            salt = generate_salt()
            print("password",password)
            print("salt",salt)

            hashed_password = hash_password(password, salt)

            conn = sqlite3.connect('user_database.db')
            cursor = conn.cursor()

            cursor.execute('INSERT INTO users (email, password, role, salt) VALUES (?, ?, ?, ?)',
                              (email, hashed_password, role, salt))

            conn.commit()
            conn.close()

            return redirect(url_for('login'))

    return render_template('register.html')
#---------------

if __name__ == '__main__':
    app.run(debug=True)
