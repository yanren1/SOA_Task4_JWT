from flask import jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from my_app import usersData, app

app.config['JWT_SECRET_KEY'] = 'my-secret-key'
jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in usersData and usersData[username]["PW"] == password:
        access_token = create_access_token(identity=username)
        return jsonify({"Message": "Taken generated! ", "Access_token": access_token}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in usersData:
        return jsonify({"error": "Username already exists"}), 400

    usersData[username] = {"username": username, "PW": password, "Role": "User"}
    return jsonify({"message": "Registered successfully"})

def admin_required(func):
    def wrapper(*args, **kwargs):
        username = get_jwt_identity()
        # print(username)
        if usersData[username]['Role'] == 'Admin':
            return func(*args, **kwargs)
        else:
            return jsonify({"error": "Error Code: 403. Unauthorized access. Admin role required."}), 403

    return wrapper


@app.route('/checkMyProfile', methods=['GET'], endpoint='checkMyProfile')
@jwt_required()
def checkMyProfile():
    current_user = get_jwt_identity()
    return jsonify({'MyProfile': usersData[current_user]})

@app.route('/checkAllProfile', methods=['GET'], endpoint='checkAllProfile')
@jwt_required()
@admin_required
def checkAllProfile():
    current_user = get_jwt_identity()
    if usersData[current_user]['Role'] == 'Admin':
        return jsonify({'All Profiles': usersData})
    else:
        return jsonify({"error": "Unauthorized access. Admin role required."}), 403

@app.route('/changeRole', methods=['PUT'], endpoint='changeRole')
@jwt_required()
@admin_required
def changeRole():
    current_user = get_jwt_identity()
    data = request.get_json()

    if data.get("username") and data.get("username") in usersData:
        if data.get("username") == current_user:
            return jsonify({'Warning': "Can't change your own role!"})
        if data.get("Role") and data.get("Role") in ["Admin", "User"]:
            usersData[data.get("username")]["Role"] = data.get("Role")
            return jsonify({'Message': f"User {data.get('username')} Role changed to {data.get('Role')}"})
        else:
            return jsonify({'Warning': "No valid role found!"})
    else:
        return jsonify({'Warning': "No valid username found!"})

@app.route('/changeMyProfile', methods=['PUT'], endpoint='changeMyProfile')
@jwt_required()
def changeMyProfile():
    current_user = get_jwt_identity()
    data = request.get_json()

    if data.get("username"):
        if data.get("username") in usersData:
            return jsonify({"error": "Username already exists"}), 400
        usersData[data.get("username")] = {"username": data.get("username"),
                                           "PW": usersData[current_user]['PW'],
                                           "Role": usersData[current_user]['Role']}
        usersData.pop(current_user)
        current_user = data.get("username")

    if data.get("password"):
        usersData[current_user]["PW"] = data.get("password")

    return jsonify({"message": "Your profile is updated."})
