from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash

# Створення і налаштування Flask додатка
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'key'
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Модель User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # хешовані паролі

# Ініціалізація бази даних
@app.before_first_request
def create_tables():
    db.create_all()

# Реєстрація користувача
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Хешування пароля перед збереженням
    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    # Створення нового користувача
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Логін для отримання JWT токену
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Перевірка, чи існує користувач
    user = User.query.filter_by(username=data['username']).first()
    
    # Перевірка правильності пароля
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid username or password"}), 401
    
    # Створення JWT токену
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

# Захищений ендпоінт
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Отримання поточного користувача з JWT токена
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello user {current_user}, you are authorized!"}), 200

# Приклад іншого захищеного ендпоінта (наприклад, список книг)
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    # Приклад даних, якщо у вас є модель Book
    books = [{"id": 1, "title": "Book 1", "author_id": 1}]
    return jsonify(books)

# Змінна для зберігання відкликаних токенів
revoked_tokens = set()

# Логіка для logout (відкликання токену)
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # JWT ID токена
    revoked_tokens.add(jti)
    return jsonify({"message": "Token revoked"}), 200

# Перевірка, чи токен був відкликаний
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens

# Запуск серверу
if __name__ == '__main__':
    app.run(debug=True)
