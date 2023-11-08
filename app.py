from flask import Flask, render_template, request, redirect, url_for, session,flash,Response

import sqlite3
import hashlib
import os
import bcrypt
import re
import csv
import io 


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
    
@app.route('/admin_page')
def admin_page():
    # Check if the user is logged in using the session
    if 'user_username' in session:
        email = session['user_username']

        # Call the function to perform the analysis
        analysis_result = analyze_personal_info()
        gender_statistics = get_gender_statistics()

        if analysis_result:
            # Render the HTML template and pass the analysis results to it
            return render_template('admin_page.html', email=email, **analysis_result,gender_statistics=gender_statistics)

        else:
            return "Analysis failed due to a database error."

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
    
@app.route('/admin_home')
def admin_home():
    # Check if the user is logged in using the session
    if 'user_username' in session:
        email = session['user_username']

        # Render the dashboard with user-specific data
        return render_template('admin_home.html', email=email)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    return redirect(url_for('login'))

@app.route('/download_data')
def download_data():
    return generate_csv()


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
# Function to generate and serve a downloadable CSV file
def generate_csv():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()

        # Query the personal_info table to fetch all records
        cursor.execute("SELECT * FROM personal_info")
        personal_info_data = cursor.fetchall()

        # Close the database connection
        conn.close()

        # Create a CSV string with the data
        output = io.StringIO()
        csv_writer = csv.writer(output)

        # Write the header row
        header = [description[0] for description in cursor.description]
        csv_writer.writerow(header)

        # Write the data rows
        for row in personal_info_data:
            csv_writer.writerow(row)

        # Set up the response to be a downloadable CSV file
        output.seek(0)
        response = Response(output, mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=personal_info_data.csv'

        return response

    except sqlite3.Error as e:
        # Handle any potential errors when connecting to the database
        print("Error:", str(e))
        return None

# Function to connect to the SQLite database and read personal_info
def analyze_personal_info():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()

        # Retrieve data from the personal_info table
        cursor.execute("SELECT zip_code, annual_income, dependents, gender FROM personal_info")
        personal_info_data = cursor.fetchall()

        # Close the database connection
        conn.close()

        # Analyze the data, for example, calculate some statistics
        total_records = len(personal_info_data)
        total_income = sum(info[1] for info in personal_info_data)
        average_income = total_income / total_records

        # Return the analysis results
        return {
            "total_records": total_records,
            "average_income": average_income,
            "personal_info_data": personal_info_data
        }

    except sqlite3.Error as e:
        # Handle any potential errors when connecting to the database
        print("Error:", str(e))
        return None
    
# Function to fetch and count gender statistics from the database
def get_gender_statistics():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()

        # Query to count the occurrences of each gender in the personal_info table
        cursor.execute("SELECT gender, COUNT(*) FROM personal_info GROUP BY gender")
        gender_data = cursor.fetchall()

        # Close the database connection
        conn.close()

        # Create a dictionary to store the gender statistics
        gender_statistics = {gender: count for gender, count in gender_data}

        return gender_statistics

    except sqlite3.Error as e:
        # Handle any potential errors when connecting to the database
        print("Error:", str(e))
        return None

# Define a function to check if a user is an admin by connecting to the SQLite database
def is_admin(email):
    # Connect to the SQLite database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    # Fetch the user's role from the database based on their email
    cursor.execute("SELECT role FROM users WHERE email=?", (email,))
    role = cursor.fetchone()

    # Close the database connection
    conn.close()

    # Check if the user's role is 'admin'
    if role and role[0] == 'admin':
        return True
    else:
        return False

def hash_password(password, salt):
    # Generate a salted hash of the password
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
   # hashed_password = bcrypt.hashpw(salted_password, bcrypt.gensalt())
    hashed_password = bcrypt.hashpw(salted_password, salt.encode('utf-8'))

    # Return the hashed password as a bytes object
    return hashed_password

def generate_salt():
    return bcrypt.gensalt().decode('utf-8')

def user_is_authenticated(email, password):
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    # Check if the email exists in the database
    cursor.execute('SELECT email, password, salt FROM users WHERE email = ?', (email,))

    user_data = cursor.fetchone()
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
            
             # Check if the user is an admin by using the is_admin function
            if is_admin(email):
                # Create a session for the admin
                session['user_username'] = email
                session['is_admin'] = True
                print("here")
                return redirect(url_for('admin_page'))  # Redirect admin to a separate admin page
            else:
                # Create a session for regular users
                session['user_username'] = email
                session['is_admin'] = False
                return redirect(url_for('protected'))  # Redirect to a protected page

        # Handle unsuccessful login (e.g., show an error message)
        else:
            # Authentication failed, show an error message using flash
            flash('Incorrect username or password. Please try again.', 'error')
            return redirect(url_for('login'))  # Redirect back to the login form
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
