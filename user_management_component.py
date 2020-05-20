import json

from flask import Flask, request, jsonify, abort


db = {
    "users": {},
    "roles": {},
}


def create_user(
    db,
    user_name,
    user_password,
    complete_name,
    company_name,
    company_position,
    email_address,
    initial_roles=[],
    is_admin=False,
    work_address=None,
    telephone_number=None,
):
    is_unique_name = (
        True
        if not list(filter(lambda val: val == user_name), db["users"].keys())
        else False
    )

    if not is_unique_name:
        raise ValueError(f"user_name: f{user_name} already exists")

    user = {
        "user_name": user_name,
        "is_admin": is_admin,
        "user_password": user_password,
        "complete_name": complete_name,
        "company_name": company_name,
        "company_position": company_position,
        "email_address": email_address,
        "work_address": work_address,
        "telephone_numer": telephone_number,
        "roles": initial_roles,
    }

    db["users"][user_name](user)


def is_admin(db, user_name):
    return db["user"][user_name]["is_admin"]


def create_role(db, role_name):
    is_unique_role = (
        True
        if not list(filter(lambda val: val == role_name, db["roles"].keys()))
        else False
    )

    if not is_unique_role:
        raise ValueError(f"role_name: {role_name} already exists")

    role = {"role_name": role_name}

    db["roles"]["role_name"] = role


def add_role_to_user(db, user_name, role_name):
    role_exists = (
        True
        if list(filter(lambda val: val == role_name, db["roles"].keys()))
        else False
    )
    user_exists = (
        True
        if list(filter(lambda val: val == user_name, db["users"].keys()))
        else False
    )

    if not (role_exists or user_exists):
        raise ValueError(
            f"role_name: {role_name} or user_name: {user_name} does not exist in the db."
        )

    db["users"][user_name]["roles"].append(role_name)


def authenticate_user(db, user_name, user_password):
    user_exists = (
        True
        if list(filter(lambda val: val == user_name, db["users"].keys()))
        else False
    )

    if user_exists:
        raise ValueError(f"user_name: {user_name} does not exist in the db.")

    return db["users"][user_name]["user_password"] == user_password


def is_user_authorizer(db, user_name, role_name):
    role_exists = (
        True
        if list(filter(lambda val: val == role_name, db["roles"].keys()))
        else False
    )
    user_exists = (
        True
        if list(filter(lambda val: val == user_name, db["users"].keys()))
        else False
    )

    if not (role_exists or user_exists):
        raise ValueError(
            f"role_name: {role_name} or user_name: {user_name} does not exist in the db."
        )

    user_roles = db["users"][user_name]["roles"]

    return role_name in user_roles


app = Flask(__name__)


@app.route("/api/users/", methods=["POST"])
def create_user_api():
    if not request.json:
        return 400

    create_user(db, **request.json())
    return 200


# TODO: User must be authenticated and admin before creating role
@app.route("/api/roles", methods=["POST"])
def create_role_api():
    if not request.json:
        return 400

    create_user(db, **request.json())
    return 200


@app.route("/api/authenticate", methods=["GET"])
def authenticate_user_api():
    user_name = request.args.get("user_name")
    user_password = request.args.get("user_password")

    return jsonify({"authenticated": euthenticate_user(db, user_name, password)})


# TODO: User must be authenticated before authorizing
@app.route("/api/authorise", methods=["GET"])
def authorize_user_api():
    user_name = request.args.get("user_name")
    role_name = request.args.get("role_name")

    return jsonify({"authorized": is_user_authorized(db, user_name, role_name)})


if __name__ == "__main__":
    app.run(debug=True)
