import sqlite3
import hashlib

# Connect to database or create it
conn = sqlite3.connect('voting.db', check_same_thread=False)
c = conn.cursor()

# Create users table with all required fields
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    roll_no TEXT PRIMARY KEY,
    name TEXT,
    password TEXT,
    email TEXT,
    phone TEXT,
    image TEXT,
    has_voted INTEGER DEFAULT 0
)
''')

# Create candidates table
c.execute('''
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    roll_no TEXT,
    role TEXT,
    image TEXT,
    votes INTEGER DEFAULT 0
)
''')

# Create admin table
c.execute('''
CREATE TABLE IF NOT EXISTS admin (
    username TEXT PRIMARY KEY,
    password TEXT
)
''')

# Create result schedule table
c.execute('''
CREATE TABLE IF NOT EXISTS result_schedule (
    id INTEGER PRIMARY KEY,
    result_date TEXT,
    is_announced INTEGER DEFAULT 0
)
''')

# Create blockchain table for vote integrity
c.execute('''
CREATE TABLE IF NOT EXISTS blockchain (
    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
    roll_no TEXT,
    candidate TEXT,
    vote_hash TEXT,
    timestamp TEXT
)
''')

# Insert default admin account if not exists
def initialize_admin():
    c.execute("SELECT * FROM admin WHERE username = ?", ("admin",))
    if c.fetchone() is None:
        c.execute("INSERT INTO admin (username, password) VALUES (?, ?)", ("admin", "admin123"))
    conn.commit()

# Register a user
def register_user(roll_no, name, password, email, phone, image):
    c.execute('SELECT * FROM users WHERE roll_no = ?', (roll_no,))
    if c.fetchone():
        return False  # Already registered
    c.execute('''
    INSERT INTO users (roll_no, name, password, email, phone, image, has_voted)
    VALUES (?, ?, ?, ?, ?, ?, 0)
    ''', (roll_no, name, password, email, phone, image))
    conn.commit()
    return True

# Authenticate user
def login_user(roll_no, password):
    c.execute('SELECT * FROM users WHERE roll_no = ? AND password = ?', (roll_no, password))
    return c.fetchone()

# Authenticate admin
def login_admin(username, password):
    c.execute('SELECT * FROM admin WHERE username = ? AND password = ?', (username, password))
    return c.fetchone()

# Add candidate
def add_candidate(name, party, role, image):
    c.execute('INSERT INTO candidates (name, roll_no, role, image, votes) VALUES (?, ?, ?, ?, 0)', (name, roll_no, role, image))
    conn.commit()

# Get all candidates
def get_candidates():
    c.execute('SELECT * FROM candidates')
    return c.fetchall()

# Record vote
def vote(roll_no, candidate_id):
    c.execute('UPDATE candidates SET votes = votes + 1 WHERE id = ?', (candidate_id,))
    c.execute('UPDATE users SET has_voted = 1 WHERE roll_no = ?', (roll_no,))
    conn.commit()

# Check if user has voted
def has_user_voted(roll_no):
    c.execute('SELECT has_voted FROM users WHERE roll_no = ?', (roll_no,))
    result = c.fetchone()
    return result and result[0] == 1

# Get vote counts
def get_results():
    c.execute('SELECT name, votes FROM candidates')
    return c.fetchall()

# Get all registered users
def get_all_users():
    c.execute('SELECT roll_no, name, email, phone, has_voted FROM users')
    return c.fetchall()

# Initialize admin account at start
initialize_admin()
