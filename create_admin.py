import sqlite3
import hashlib
import os
import getpass
import bcrypt

# Function to generate a random salt
def generate_salt():
    return bcrypt.gensalt().decode('utf-8')

# Function to hash the password using a salt
def hash_password(password, salt):
    # Generate a salted hash of the password
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
   # hashed_password = bcrypt.hashpw(salted_password, bcrypt.gensalt())
    hashed_password = bcrypt.hashpw(salted_password, salt.encode('utf-8'))

    # Return the hashed password as a bytes object
    return hashed_password


def create_eatery(email, password):
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    try:
        # Connect to the SQLite database (or create it if it doesn't exist)
        with sqlite3.connect('user_database.db') as conn:
            cursor = conn.cursor()

            # Create the users table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY,
                    password TEXT,
                    salt TEXT,
                    role TEXT
                )
            ''')

            # Check if the email already exists in the database
            cursor.execute("SELECT email FROM users WHERE email=?", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                print("User with this email already exists.")
            else:
                # Insert the new eatery with role 'admin' into the users table
                cursor.execute("INSERT INTO users (email, password, salt, role) VALUES (?, ?, ?, ?)", (email, hashed_password, salt, 'admin'))
                conn.commit()
                print("Eatery created successfully")

    except sqlite3.Error as e:
        print("SQLite error:", e)

if __name__ == '__main__':
    email = input("Enter email: ")
    password = getpass.getpass("Enter password: ")  # Hide password input
    create_eatery(email, password)
