from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt # pip install pyjwt.PyJWT is a Python library which allows you to encode and decode JSON Web Tokens (JWT)
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/sagar/Documents/SQLite_Database/flask_restful/todo.db'

db = SQLAlchemy(app)


class User(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	public_id = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50))
	password =db.Column(db.String(50))
	admin = db.Column(db.Boolean)


class Todo(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	text = db.Column(db.String(50))
	user_id =db.Column(db.Integer)
	complete = db.Column(db.Boolean)

def token_required(f):	
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None

		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message': 'Token is missing!'})

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			#data['public_id'] will have public id of the authenticated user. login() had encoded the jwt token out of the user's public_id. Check its implementation below in login()
			current_user = User.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message':'Token is invalid'}), 401

		return f(current_user, *args, **kwargs)
	
	return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user): #To mimic this API call via Postman, include 'x-access-token' with the token value obtained from login call

	if not current_user.admin:
		return jsonify({'message':'You are not authorized to see all users!'})

	users = User.query.all()
	output = []
	for user in users:
		user_data = {}
		user_data['public_id'] = user.public_id
		user_data['name'] = user.name
		user_data['password'] = user.password
		user_data['admin'] = user.admin
		output.append(user_data)

	return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user,public_id):

	if not current_user.admin:
		return jsonify({'message':'You are not authorized see ny user data!'})

	user = User.query.filter_by( public_id=public_id ).first()
	if not user:
		return jsonify({'message':'User not found!'})

	user_data = {}
	user_data['public_id'] = user.public_id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin
	return jsonify({'user':user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

	if not current_user.admin:
		return jsonify({'message':'You are not authorized to create a user!'})

	data = request.get_json()
	print('Data is %s', data)
	hashed_pwd = generate_password_hash(data['password'], method='sha256')
	new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pwd, admin=False)
	db.session.add(new_user)
	db.session.commit()
	return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
	if not current_user.admin:
		return jsonify({'message':'You are not authorized to promote a user!'})

	user = User.query.filter_by( public_id=public_id ).first()
	if not user:
		return jsonify({'message':'User not found!'})

	user.admin = True
	db.session.commit()
	return jsonify({'message': 'The user has been promoted!'})

@app.route('/user/demote/<public_id>', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message':'You are not authorized to demote any user!'})

	user = User.query.filter_by( public_id=public_id ).first()
	if not user:
		return jsonify({'message':'User not found!'})

	user.admin = False
	db.session.commit()
	return jsonify({'message': 'The user has been demoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message':'You are not authorized to delete a user!'})

	user = User.query.filter_by( public_id=public_id ).first()
	if not user:
		return jsonify({'message':'User not found!'})

	db.session.delete(user)
	db.session.commit()
	return jsonify({'message': 'The user has been deleted!'})

@app.route('/login')
def login(): #To mimic this API call ia Postman, select GET as http protocol and in the Authorization section, select Basic Auth. Enter username and password to invoke the API
	auth = request.authorization
	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required!"'})

	user = User.query.filter_by(name=auth.username).first()

	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required!"'})

	if check_password_hash( user.password, auth.password):
		token = jwt.encode({'public_id':user.public_id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(seconds=300)}, app.config['SECRET_KEY'])

		return jsonify({'token': token.decode('UTF-8')})

	return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required!"'})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
	todos = Todo.query.filter_by(user_id=current_user.id).all()
	output = []
	for todo in todos:
		todo_data = {}
		todo_data['id'] = todo.id
		todo_data['text'] = todo.text
		todo_data['complete'] = todo.complete
		output.append( todo_data )
	return jsonify({'todos':output})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user,todo_id):
	todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
	if not todo:
		return jsonify({'message':'No todo found!'})
	todo_data = {}
	todo_data['id'] = todo.id
	todo_data['text'] = todo.text
	todo_data['complete'] = todo.complete	
	return todo_data

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
	data = request.get_json()

	new_todo = Todo(text=data['text'], complete=False, user_id = current_user.id)
	db.session.add(new_todo)
	db.session.commit()
	return jsonify({'message':'Todo created!'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
	todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
	if not todo:
		return jsonify({'message':'No todo found!'})

	todo.complete = True
	db.session.commit()

	return jsonify({'message':'Todo item has been marked completed'})

	return ''


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
	todo = Todo.query.filter_by( id=todo_id, user_id=current_user.id).first()
	if not todo:
		return jsonify({'message':'No todo found!'})

	db.session.delete(todo)
	db.session.commit()
	return jsonify({'message': 'The todo item has been deleted!'})

	
if __name__ == '__main__':
	app.run(debug = True)
