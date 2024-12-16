from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

# Ініціалізація Flask додатка
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Модель User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Хешований пароль

# Створення таблиць
@app.before_first_request
def create_tables():
    db.create_all()

# Валідація вхідних даних
def validate_data(data, keys):
    if not data:
        return "No data provided", 400
    for key in keys:
        if key not in data:
            return f"Missing '{key}' in request data", 400
    return None, 200

# Реєстрація користувача
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    error, status = validate_data(data, ["username", "password"])
    if error:
        return jsonify({"message": error}), status

    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

# Логін для отримання токена
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    error, status = validate_data(data, ["username", "password"])
    if error:
        return jsonify({"message": error}), status

    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

# Захищений ендпоінт
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello user {current_user}, you are authorized!"}), 200

# Ендпоінт для отримання книг
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    # Приклад даних, якщо у вас немає реальної моделі Book
    books = [
        {"id": 1, "title": "The Catcher in the Rye", "author": "J.D. Salinger"},
        {"id": 2, "title": "To Kill a Mockingbird", "author": "Harper Lee"}
    ]
    return jsonify(books), 200

# Логіка для logout (відкликання токену)
revoked_tokens = set()

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    revoked_tokens.add(jti)
    return jsonify({"message": "Token revoked"}), 200

# Перевірка відкликаного токена
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens

# Health check
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

# Запуск серверу
if __name__ == '__main__':
    app.run(debug=True)
