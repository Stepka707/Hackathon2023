from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user


import sqlite3
import hashlib
import os
import bcrypt


app = Flask(__name__)
app.secret_key = 'your_secret_key'

#---------POSIBLE CAN BE DELETED----------
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, email):
        self.email = email

    def get_id(self):
        return self.email

login_manager = LoginManager(app)

# Define a function to query the database and load a user by email
@login_manager.user_loader
def load_user(email):
    connection = sqlite3.connect('user_database.db')  
    cursor = connection.cursor()
    cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
    user_data = cursor.fetchone()
    connection.close()

    if user_data:
        return User(user_data[0])  # Create a User instance with the email
    else:
        return None  # User not found
#---------------------------------

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

#@app.route('/submit', methods=['POST'])
#def submit():
 #  if request.method == 'POST':
   #     name = request.form['name']
   #     email = request.form['email']
   #     message = request.form['message']

        # Connect to the SQLite database
     #   conn = sqlite3.connect('mydatabase.db')
     #   cursor = conn.cursor()

        # Create a table if it doesn't exist
       # cursor.execute('''
        #    CREATE TABLE IF NOT EXISTS contacts (
         #       name TEXT,
          #      email TEXT,
          #      message TEXT
          #  )
       # ''')

        # Insert data into the table
       # cursor.execute('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)', (name, email, message))

       # conn.commit()
       # conn.close()

       # return redirect(url_for('form'))

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
           # hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8'))
            hashed_password = hash_password(password,salt)
            print("password",password)
            print("salt",salt)
            print("hashed_password",hashed_password)
            print("stored_password",stored_password)

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
