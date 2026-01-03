"""
SQL Injection Secure Implementation - Python Flask with SQLAlchemy
Demonstrates proper defense mechanisms using SQLite
"""

from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

app = Flask(__name__)

# Database connection using SQLAlchemy with SQLite
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'sqlite.db')
CONNECTION_STRING = f"sqlite:///{DB_PATH}"

engine = create_engine(CONNECTION_STRING)
Session = sessionmaker(bind=engine)


@app.route('/api/login', methods=['POST'])
def login():
    """
    SECURE: Uses parameterized queries
    Protected against SQL injection
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # SECURITY: Parameterized query with bound parameters
    query = text(
        "SELECT UserId, Username, Email, Role "
        "FROM Users "
        "WHERE Username = :username AND PasswordHash = :password"
    )
    
    try:
        session = Session()
        result = session.execute(query, {'username': username, 'password': password})
        row = result.fetchone()
        session.close()
        
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
    SECURE: Uses parameterized queries with LIKE operator
    Protected against SQL injection
    """
    search_term = request.args.get('q', '')
    
    # SECURITY: Parameterized query - SQLAlchemy handles escaping
    query = text(
        "SELECT PostId, Title, Content "
        "FROM Posts "
        "WHERE Title LIKE :search_pattern OR Content LIKE :search_pattern"
    )
    
    try:
        session = Session()
        # Prepare the search pattern safely
        search_pattern = f"%{search_term}%"
        result = session.execute(query, {'search_pattern': search_pattern})
        
        posts = []
        for row in result.fetchall():
            posts.append({
                'id': row[0],
                'title': row[1],
                'content': row[2]
            })
        
        session.close()
        return jsonify({'success': True, 'posts': posts})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'running', 'version': 'secure'})


if __name__ == '__main__':
    print("=" * 60)
    print("Secure Flask Application - SQL Injection Protected")
    print("Using parameterized queries via SQLAlchemy")
    print("=" * 60)
    app.run(debug=True, port=5002)

