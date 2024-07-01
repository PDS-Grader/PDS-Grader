import sqlite3
import bcrypt

# Initialize the database and create a users table
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to add a new user
def add_user(username, password):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username.lower(), password_hash.decode('utf-8')))
    conn.commit()
    conn.close()

# Initialize the database and add sample users
init_db()
