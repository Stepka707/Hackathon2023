from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

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

if __name__ == '__main__':
    app.run(debug=True)
