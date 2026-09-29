from flask import Flask, request, jsonify, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime

app = Flask(__name__)
# A secret key is required to use Flask sessions securely
app.secret_key = 'super_secret_quick_note_key' 

def init_db():
    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Create notes table with user_id foreign key
    c.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('index.html')

# --- AUTHENTICATION ROUTES ---

@app.route('/auth/status', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'username': session['username']})
    return jsonify({'logged_in': False})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect('notes.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    c.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = user[1]
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# --- NOTES ROUTES (Updated to check user_id) ---

@app.route('/notes', methods=['GET'])
def get_notes():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    # Only fetch notes belonging to the logged-in user
    c.execute('SELECT id, content, timestamp FROM notes WHERE user_id = ? ORDER BY id DESC', (session['user_id'],))
    notes = [{'id': row[0], 'content': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(notes)

@app.route('/notes', methods=['POST'])
def add_note():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'error': 'Content is required'}), 400
        
    timestamp = datetime.datetime.now().strftime("%b %d, %I:%M %p")
        
    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    c.execute('INSERT INTO notes (user_id, content, timestamp) VALUES (?, ?, ?)', (session['user_id'], content, timestamp))
    conn.commit()
    note_id = c.lastrowid
    conn.close()
    
    return jsonify({'id': note_id, 'content': content, 'timestamp': timestamp}), 201

@app.route('/notes/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    c.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (note_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 200

@app.route('/notes/<int:note_id>', methods=['PUT'])
def update_note(note_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'error': 'Content is required'}), 400
        
    timestamp = datetime.datetime.now().strftime("%b %d, %I:%M %p") + " (Edited)"
    
    conn = sqlite3.connect('notes.db')
    c = conn.cursor()
    c.execute('UPDATE notes SET content = ?, timestamp = ? WHERE id = ? AND user_id = ?', (content, timestamp, note_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'id': note_id, 'content': content, 'timestamp': timestamp}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)