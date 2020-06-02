import os

from flask import Flask, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pass_lib
from itsdangeorus import JSONWebSignatureSerializer, BadSignature, SignatureExpired

"""
    Configuración de la API en Flask
"""
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '3df9bbf3-1a43-43db-9ebb-f395cf555491')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
token_serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])

user_role_table = db.Table(
    'user_role',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
)

"""
    Modelo de usuario
"""
class User(db.Model):

    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(32), index=True, unique=True)
    password = db.Column(db.String(64))
    is_admin = db.Column(db.Boolean)
    roles = db.relationship('Role', secondary=user_role_table, backref=db.backref('users', lazy='dynamic'))

    """
        Envía la contraseña encriptada
        :password Contraseña a encriptar
    """
    def set_password(self, password):
        self.password = pass_lib.encrypt(password)

    """
        Autenticar contraseña
        :password Contraseña que se va a autenticar
    """
    def authenticate(self, password):
        return pass_lib.verify(password, self.password)

    """
        Convertir la información del usuario en un diccionario para manejar JSON
    """
    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'is_admin': self.is_admin,
            'roles': [
                role.to_dict() for role in self.roles
            ]
        }

    """
        Obtener el token con el cual el usuario se va a autenticar
        :password Contraseña a encriptar
    """
    def get_token(self):
        return token_serializer.dumps(self.to_dict())

"""
    Modelo de Rol
"""
class Role(db.Model):

    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))

    """
        Convertir la información del rol en un diccionario para manejar JSON
    """
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
        }

"""
    Verificar que el token enviado sea válido
    :token Token que se va a validar
"""
def validate_token(token):
    try:
        data = token_serializer.loads(token)
    except BadSignature:
        return None

    return data

"""
    Endpoint que permite la creación de un usuario en la base de datos
"""
@app.route('/api/user', methods=['POST'])
def create_user_api():
    user_name = request.json.get('user_name')
    password = request.json.get('password')
    is_admin = request.json.get('is_admin')
    token = request.json.get('auth_token')

    if is_admin:
        user_data = validate_token(token)
        if not user_data or not user_data['is_admin']:
            abort(400)

    user = User(user_name=user_name)
    user.is_admin = is_admin
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict), 200

"""
    Endpoint que permite la creación de un rol para un usuario en la base de datos
"""
@app.route('/api/user/add_role', methods=['POST'])
def add_role_api():
    token = request.json.get('token')
    role = request.json.get('role')

    user = validate_token(token)
    if not user:
        abort(400)

    user = User.query.get(user['id'])
    role = Role.query.filter(Role.name == role).first()

    user.roles.append(role)
    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict), 200

"""
    Endpoint que permite la autenticación de un usuario
"""
@app.route('/api/authenticate', methods=['POST'])
def authenticate_api():
    user_name = request.json.get('user_name')
    password = request.json.get('password')

    if None in (user_name, password):
        abort(400)

    user = User.query.filter_by(user_name=user_name).first()
    if user is None:
        abort(400)

    if not user.authenticate(password):
        return jsonify({
            'authenticated': False
        }), 200

    return jsonify({
        'authenticated': True,
        'auth_token': user.get_token()
    }), 200

"""
    Endpoint que le permite a un usuario acceder a los recursos autorizados
"""
@app.route('/api/autorize', method=['POST'])
def authorize_api():
    token = request.json.get('auth_token')
    role = request.json.get('role')

    user_data = validate_token(token)

    if not user_data:
        abort(400)

    if role not in map(lambda data: data['name'], user_data['roles']):
        return jsonify({
            'authorized': False
        }), 200

    return jsonify({
        'authorized': True
    }), 200