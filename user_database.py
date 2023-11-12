import sqlite3
import hashlib
import os

# Define a function to create the SQLite database and user table
def create_database():
    # Check if the database file exists; if not, create it
    if not os.path.exists('nalam_database.db'):
        conn = sqlite3.connect('nalam_database.db')
        cursor = conn.cursor()

        # Create a user table with fields for username, email, and hashed password   
        cursor.execute('''         
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                visiting TEXT CHECK (visiting IN ('yes', 'no')),
                donation_amount REAL,
                salt TEXT    
                       
            )
        ''')

        conn.commit()
        conn.close()
        print("Database created successfully.")
    else:
        print("Database already exists.")

# Call the function to create the database and user table
create_database()
