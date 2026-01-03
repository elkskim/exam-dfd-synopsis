"""
SQL Injection Vulnerable Implementation - Python Flask with SQLite
INTENTIONALLY INSECURE - For educational purposes only
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# Database connection - using SQLite
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'sqlite.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABLE: Uses string formatting to build SQL query
    Susceptible to SQL injection attacks
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Direct string concatenation
    query = f"SELECT UserId, Username, Email, Role FROM Users WHERE Username = '{username}' AND PasswordHash = '{password}'"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # Executing unsanitized query
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return jsonify({
                'success': True,
                'user': {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'role': row[3]
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/posts/search', methods=['GET'])
def search_posts():
    """
    VULNERABLE: Uses string formatting for search queries
    Susceptible to UNION-based SQL injection
    """
    search_term = request.args.get('q', '')
    
    # VULNERABILITY: Direct string concatenation
    query = f"SELECT PostId, Title, Content FROM Posts WHERE Title LIKE '%{search_term}%' OR Content LIKE '%{search_term}%'"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)  # Executing unsanitized query
        
        posts = []
        for row in cursor.fetchall():
            posts.append({
                'id': row[0],
                'title': row[1],
                'content': row[2]
            })
        
        conn.close()
        return jsonify({'success': True, 'posts': posts})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'running', 'version': 'vulnerable'})


if __name__ == '__main__':
    print("=" * 60)
    print("WARNING: This is an INTENTIONALLY VULNERABLE application!")
    print("For educational purposes only - DO NOT use in production")
    print("=" * 60)
    app.run(debug=True, port=5001)

