import datetime
import urllib3
import uuid
import json
from urllib.parse import unquote
import logging
from app import app, mongo
import keycloakutils
from urllib.parse import urlparse
from flask import request, jsonify, make_response, g, redirect
from flask_oidc import OpenIDConnect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s\t[%(levelname)s]\t%(message)s')
logger = logging.getLogger()
if app.config['DEBUG']:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

oidc = OpenIDConnect(app)
keycloak = keycloakutils.Keycloak(str(app.config['KEYCLOAK_URL']), str(app.config['KEYCLOAK_REALM']),
                                  str(app.config['KEYCLOAK_CLIENT_SECRET']), str(app.config['KEYCLOAK_CLIENT_ID']))


# *************************** VERSION ************************** #
# VERIFIED
@app.route('/', methods=['GET'])
def api_version():
    logger.info("Fetching current API details")
    try:
        logger.info("Current API details fetched")
        return jsonify({"status": True, "version": "v" + str(app.config['API_VERSION']),
                        "request_type": "JSON", "response_type": "JSON"})
    except Exception as e:
        logger.error("Current API details fetch error: " + str(e))
        return jsonify({"status": False, "msg": str(e)}), 500


# *************************** VERSION ************************** #


# *********************** AUTHENTICATION *********************** #
# VERIFIED
@app.route('/login', methods=['GET'])
@oidc.require_login
def login():
    if request.args.get('redirect_url'):
        redirect_url = unquote(str(request.args.get('redirect_url')))
        response = make_response(redirect(redirect_url))
        parsed_uri = urlparse(redirect_url)
        url = '{uri.netloc}'.format(uri=parsed_uri)
        domain = str(url).split(":")[0]
        logger.info(domain)
    else:
        return jsonify({"status": False, "msg": "redirect_url not found in query parameter"})

    if oidc.user_loggedin:
        if oidc.get_access_token() is not None:
            response.set_cookie("authorization", value=str(oidc.get_access_token()), httponly=False, domain=domain)
        else:
            response.set_cookie('authorization', '', expires=0)
            response.set_cookie('oidc_id_token', '', expires=0)
            response.set_cookie('session', '', expires=0)
    return response


# VERIFIED
@app.route('/authenticate', methods=['GET'])
def authenticate():
    logger.info("Authenticating user")
    try:
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
            logger.error("Username/Password not found in the request")
            return jsonify({"status": False, "msg": "Username/Password not found"}), 401

        result = keycloak.get_token(str(auth.username), str(auth.password))
        if result['status']:
            logger.info("User authenticated with username: " + str(auth.username))
            return jsonify({"status": True, "access_token": str(result['response']['access_token'])})
        else:
            logger.error("Incorrect username or password")
            return jsonify({"status": False, "msg": "Incorrect username or password"}), 401
    except Exception as e:
        logger.error("User authentication error: " + str(e))
        return jsonify({"status": False, "msg": str(e)}), 500


# VERIFIED
@app.route('/currentUser', methods=['GET'])
@oidc.accept_token(require_token=True, render_errors=False)
def current_user_details():
    logger.info("Fetching current user details")
    try:
        output = dict()
        output["id"] = str(g.oidc_token_info['user_id'])
        output["first_name"] = str(g.oidc_token_info['user_first_name'])
        output["last_name"] = str(g.oidc_token_info['user_last_name'])
        output["phone"] = str(g.oidc_token_info['user_phone'])
        output["email"] = str(g.oidc_token_info['user_email'])
        output["username"] = str(g.oidc_token_info['user_username'])
        output["roles"] = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]

        logger.info("Current user details fetched for user with user_id: " + str(output["id"]))
        return jsonify({"status": True, "user": dict(output)})
    except Exception as e:
        logger.error("Current user details fetch error: " + str(e))
        return jsonify({"status": False, "msg": str(e)}), 500


# *********************** AUTHENTICATION *********************** #


# **************************** USER **************************** #

# VERIFIED
@app.route('/users', methods=['GET'])
@oidc.accept_token(require_token=True, render_errors=False)
def all_users_details():
    logger.info("Fetching list of all users by: " + str(g.oidc_token_info['user_id']))

    try:
        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not allowed to perform the operation")
            return jsonify({"status": False, "msg": "You are not allowed to perform the operation"}), 401

        all_users_output = keycloak.get_users(str(request.headers['Authorization']).lstrip("Bearer"))
        if all_users_output['status']:
            logger.info("All User details fetched")
            return jsonify({"status": True, 'users': all_users_output['response']}), 200
        else:
            logger.error("All User details fetch error: " + all_users_output['msg'])
            return jsonify({"status": False, "msg": all_users_output['msg']}), int(all_users_output['error_code'])
    except Exception as e:
        logger.error("All user fetch error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# VERIFIED
@app.route('/user', methods=['GET'])
@oidc.accept_token(require_token=True, render_errors=False)
def user_details():
    logger.info("Fetching user details by: " + str(g.oidc_token_info['user_id']))

    try:
        user_id = request.args.get("user_id")
        if user_id is None:
            return jsonify({"status": False, "msg": "'user_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        all_users_output = keycloak.get_users(str(request.headers['Authorization']).lstrip("Bearer"),
                                              user_id=str(user_id))
        if all_users_output['status']:
            if len(all_users_output['response']) == 1:
                logger.info("User details fetched with user_id: " + str(user_id))
                return jsonify({"status": True, "user": all_users_output['response'][0]}), 200
        else:
            logger.error("User details fetch error: " + all_users_output['msg'])
            return jsonify({"status": False, "msg": all_users_output['msg']}), int(all_users_output['error_code'])
    except Exception as e:
        logger.info("User details fetch error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# VERIFIED
@app.route('/user', methods=['POST'])
@oidc.accept_token(require_token=True, render_errors=False)
def add_user():
    logger.info("Adding new user details by: " + str(g.oidc_token_info['user_id']))

    try:
        json_data = request.get_json()

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        add_users_output = keycloak.add_user(str(request.headers['Authorization']).lstrip("Bearer"), json_data)
        if add_users_output['status']:
            logger.info("User added with user_id: " + str(add_users_output['response']['user_id']))
            return jsonify({"status": True, "user": {"id": str(add_users_output['response']['user_id'])}}), 200
        else:
            logger.error("User add error: " + add_users_output['msg'])
            return jsonify({"status": False, "msg": add_users_output['msg']}), int(add_users_output['error_code'])

    except Exception as e:
        logger.error("User add error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# VERIFIED
@app.route('/user', methods=['PUT'])
@oidc.accept_token(require_token=True, render_errors=False)
def edit_user():
    logger.info("Updating user details by: " + str(g.oidc_token_info['user_id']))

    try:
        json_data = request.get_json()

        user_id = request.args.get("user_id")
        if user_id is None:
            return jsonify({"status": False, "msg": "'user_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        edit_users_output = keycloak.edit_user(str(request.headers['Authorization']).lstrip("Bearer"), user_id,
                                               json_data)
        if edit_users_output['status']:
            logger.info("User edited with user_id: " + str(edit_users_output['response']['user_id']))
            return jsonify({"status": True, "user": {"id": str(edit_users_output['response']['user_id'])}}), 200
        else:
            logger.error("User edit error: " + edit_users_output['msg'])
            return jsonify({"status": False, "msg": edit_users_output['msg']}), int(edit_users_output['error_code'])

    except Exception as e:
        logger.error("User edit error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# VERIFIED
@app.route('/resetPassword', methods=['PUT'])
@oidc.accept_token(require_token=True, render_errors=False)
def reset_password():
    logger.info("Changing Password for user by: " + str(g.oidc_token_info['user_id']))

    try:
        user_id = request.args.get("user_id")
        if user_id is None:
            return jsonify({"status": False, "msg": "'user_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        password_reset_output = keycloak.reset_password(str(request.headers['Authorization']).lstrip("Bearer"),
                                                        user_id, "windo123")
        if password_reset_output['status']:
            logger.info("Password reset done for user_id: " + str(password_reset_output['response']['user_id']))
            return jsonify({"status": True, "user": {"id": str(password_reset_output['response']['user_id'])}}), 200
        else:
            logger.error("Password reset error: " + password_reset_output['msg'])
            return jsonify({"status": False, "msg": password_reset_output['msg']}), int(
                password_reset_output['error_code'])
    except Exception as e:
        logger.error("Password reset error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# VERIFIED
@app.route('/user', methods=['DELETE'])
@oidc.accept_token(require_token=True, render_errors=False)
def delete_user():
    logger.info("Deleting user details by: " + str(g.oidc_token_info['user_id']))

    try:
        user_id = request.args.get("user_id")
        if user_id is None:
            return jsonify({"status": False, "msg": "'user_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        user_delete_output = keycloak.delete_user(str(request.headers['Authorization']).lstrip("Bearer"), user_id)
        if user_delete_output['status']:
            logger.info("User deleted with user_id: " + str(user_delete_output['response']['user_id']))
            return jsonify({"status": True, "user": {"id": str(user_delete_output['response']['user_id'])}}), 200
        else:
            logger.error("User delete error: " + user_delete_output['msg'])
            return jsonify({"status": False, "msg": user_delete_output['msg']}), int(
                user_delete_output['error_code'])
    except Exception as e:
        logger.error("User delete error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# **************************** USER **************************** #


# **************************** CUSTOMER **************************** #

# TESTED
@app.route('/customers', methods=['GET'])
@oidc.accept_token(require_token=True, render_errors=False)
def all_customers_details():
    logger.info("Fetching list of all customers by: " + str(g.oidc_token_info['user_id']))

    try:
        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if "admin" not in current_user_roles:
            logger.error("User is not allowed to perform the operation")
            return jsonify({"status": False, "msg": "You are not allowed to perform the operation"}), 401

        user = mongo.db.customersCollection
        all_user = []

        for u in user.find().sort("first_name"):
            tmp = u
            tmp["id"] = tmp["_id"]
            del tmp["_id"]
            all_user.append(dict(tmp))

        logger.info("All Customer details fetched")
        return jsonify({"status": True, 'customers': all_user}), 200

    except Exception as e:
        logger.error("All user fetch error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# TESTED
@app.route('/customer', methods=['GET'])
@oidc.accept_token(require_token=True, render_errors=False)
def customer_details():
    logger.info("Fetching customer details by: " + str(g.oidc_token_info['user_id']))

    try:
        customer_id = request.args.get("customer_id")
        if customer_id is None:
            return jsonify({"status": False, "msg": "'customer_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if not any(s in current_user_roles for s in ["admin", "manager"]) and g.oidc_token_info['user_id'] \
                != customer_id:
            logger.error("customer is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        customer = mongo.db.customersCollection
        output = customer.find_one({"_id": str(customer_id).strip()})

        if output is None:
            logger.error("customer not found with id: " + str(customer_id))
            return jsonify({"status": False, "msg": "customer not found with specified ID"}), 401

        output['id'] = str(output['_id'])
        # del output["user_id"]
        del output["_id"]
        del output["password"]

        logger.info("customer details fetched with customer_id: " + str(customer_id))
        return jsonify({"status": True, "customer": output}), 200

    except Exception as e:
        logger.info("customer details fetch error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# TESTED
@app.route('/customer', methods=['POST'])
@oidc.accept_token(require_token=True, render_errors=False)
def add_customer():
    logger.info("Adding new customer details by: " + str(g.oidc_token_info['user_id']))
    try:
        json_data = request.get_json()

        if not all(s in json_data for s in ["first_name", "last_name", "username", "phone", "password", "email"]):
            return jsonify({"status": False, "msg": "'first_name', 'last_name', 'username', 'phone', 'email'"
                                                    " and/or 'password' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if not any(s in current_user_roles for s in ["admin", "manager"]):
            logger.error("customer is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401
        customer = mongo.db.customersCollection
        row_count = customer.find({"first_name": str(json_data["first_name"]).strip()}).count()
        if int(row_count) > 0:
            logger.error("first name already exists")
            return jsonify({"status": False, "msg": "first name already exists"}), 409

        row_count = customer.find({"username": str(json_data["username"]).strip()}).count()
        if int(row_count) > 0:
            logger.error("username already exists")
            return jsonify({"status": False, "msg": "username already exists"}), 409

        row_count = customer.find({"phone": str(json_data["phone"]).strip()}).count()
        if int(row_count) > 0:
            logger.error("Mobile number already exists")
            return jsonify({"status": False, "msg": "Mobile number already exists"}), 409

        if "email" in json_data.keys():
            row_count = customer.find({"email": str(json_data["email"]).strip()}).count()
            if int(row_count) > 0:
                logger.error("Email already exists")
                return jsonify({"status": False, "msg": "Email already exists"}), 409

        if len(json_data["password"]) < 6 or len(json_data["password"]) > 32:
            logger.error("Password length is not in range(Min 6 char required and Max 32 char)")
            return jsonify({"status": False, "msg": "Password length is not in range(Min 6 char required and Max 32 "
                                                    "char)"}), 400

        json_data["password"] = generate_password_hash(json_data['password'], method='sha256')

        json_data["_id"] = str(uuid.uuid4())
        json_data["roles"] = ["customer"]
        add_users_output = keycloak.add_user(str(request.headers['Authorization']).lstrip("Bearer"), json_data)
        if add_users_output['status']:
            logger.info("Customer added with customer_id: " + str(add_users_output['response']['user_id']))
            json_data["user_id"] = str(add_users_output['response']['user_id'])
            customer = mongo.db.customersCollection
            customer_id = customer.insert_one(json_data)
            del json_data["password"]

            logger.info("customer added with customer_id: " + str(customer_id.inserted_id))
            # return jsonify({"status": True, "user": {"id": str(add_users_output['response']['user_id'])}}), 200
            return jsonify({"status": True, "customer": {"id": customer_id.inserted_id}}), 200
        else:
            logger.error("User add error: " + add_users_output['msg'])
            return jsonify({"status": False, "msg": add_users_output['msg']}), int(add_users_output['error_code'])

    except Exception as e:
        logger.error("customer add error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# TESTED
@app.route('/customer', methods=['PUT'])
@oidc.accept_token(require_token=True, render_errors=False)
def edit_customer():
    logger.info("Updating customer details by: " + str(g.oidc_token_info['user_id']))

    try:
        json_data = request.get_json()
        customer = mongo.db.customersCollection

        customer_id = request.args.get("customer_id")
        if customer_id is None:
            return jsonify({"status": False, "msg": "'customer_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if not any(s in current_user_roles for s in ["admin"]) and g.oidc_token_info['user_id'] != customer_id:
            logger.error("customer is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        data_keys = json_data.keys()

        this_customer = customer.find_one({"_id": str(customer_id).strip()})
        if this_customer is None:
            logger.error("No customer found with the id for edit customer")
            return jsonify({"status": False, "msg": "No customer found with the id for edit customer"}), 404

        if "first_name" in data_keys:
            if json_data["first_name"] != this_customer["first_name"]:
                row_count = customer.find({"first_name": str(json_data["first_name"]).strip()}).count()
                if int(row_count) > 0:
                    logger.error("first_name already exists")
                    return jsonify({"status": False, "msg": "first_name already exists"}), 409

        if "phone" in data_keys:
            if json_data["phone"] != this_customer["phone"]:
                row_count = customer.find({"phone": str(json_data["phone"]).strip()}).count()
                if int(row_count) > 0:
                    logger.error("Mobile number already exists")
                    return jsonify({"status": False, "msg": "Mobile number already exists"}), 409

        if "email" in data_keys:
            if json_data["email"] != this_customer["email"]:
                row_count = customer.find({"email": str(json_data["email"]).strip()}).count()
                if int(row_count) > 0:
                    logger.error("Email already exists")
                    return jsonify({"status": False, "msg": "Email already exists"}), 409

        if "password" in data_keys:
            logger.warning("Found password in customer update data. Removing password")
            del json_data["password"]

        if "id" in data_keys:
            logger.warning("Found ID in customer update data. Removing ID")
            del json_data["id"]

        # output = \
        customer.update_one({"_id": str(customer_id).strip()}, {"$set": dict(json_data)})
        # if output.matched_count < 1:
        #    logger.error("No customer found with the id for edit customer")
        #    return jsonify({"status": False, "msg": "No customer found with the id for edit customer"}), 404

        logger.info("customer details update with customer_id: " + str(customer_id))
        return jsonify({"status": True, "customer": {"id": customer_id}}), 200
    except Exception as e:
        logger.error("customer details update error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# TESTED
@app.route('/changePassword', methods=['PUT'])
@oidc.accept_token(require_token=True, render_errors=False)
def change_password():
    logger.info("Changing Password for customer by: " + str(g.oidc_token_info['user_id']))

    try:
        json_data = request.get_json()
        customer = mongo.db.customersCollection

        customer_id = request.args.get("customer_id")
        if customer_id is None:
            return jsonify({"status": False, "msg": "'customer_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if not any(s in current_user_roles for s in ["admin"]) and g.oidc_token_info['user_id'] != customer_id:
            logger.error("customer is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        if len(json_data["password"]) < 6:
            logger.error("Password is too short(Min 6 char required)")
            return jsonify({"status": False, "msg": "Password is too short(Min 6 char required)"}), 400
        elif len(json_data["password"]) > 32:
            logger.error("Password can't be more than 32 char")
            return jsonify({"status": False, "msg": "Password can't be more than 32 char"}), 400

        json_data["password"] = generate_password_hash(json_data['password'], method='sha256')

        output = customer.update_one({"_id": str(customer_id).strip()}, {"$set": {"password": json_data["password"]}})

        if output.matched_count < 1:
            logger.error("No customer found with the id for change password")
            return jsonify({"status": False, "msg": "No customer found with the id for change password"}), 404

        logger.info("Password updated for customer with customer_id: " + str(customer_id))
        return jsonify({"status": True, "customer": {"id": str(customer_id).strip()}}), 200
    except Exception as e:
        logger.error("Password update error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500


# TESTED
@app.route('/customer', methods=['DELETE'])
@oidc.accept_token(require_token=True, render_errors=False)
def delete_customer():
    logger.info("Deleting customer details by: " + str(g.oidc_token_info['user_id']))

    try:
        customer = mongo.db.customersCollection

        customer_id = request.args.get("customer_id")
        if customer_id is None:
            return jsonify({"status": False, "msg": "'customer_id' not found in query."}), 404

        current_user_roles = [grp.lstrip('/') for grp in g.oidc_token_info['user_group']]
        if not any(s in current_user_roles for s in ["admin"]):
            logger.error("User is not authorized to perform the operation")
            return jsonify({"status": False, "msg": "You are not authorized to perform the operation"}), 401

        if str(customer_id).strip() == g.oidc_token_info['user_id']:
            logger.error("customer can't delete current logged in customer")
            return jsonify({"status": False, "msg": "You can't delete current logged in customer"}), 400

        output = customer.delete_one({"_id": str(customer_id).strip()})
        if output.deleted_count < 1:
            logger.error("No customer found with the id for delete customer")
            return jsonify({"status": False, "msg": "No customer found with the id for delete customer"}), 400

        logger.info("customer deleted with customer_id: " + str(customer_id))
        return jsonify({"status": True, "customer": {"id": customer_id}}), 200
    except Exception as e:
        logger.error("customer delete error: " + str(e))
        return jsonify({"status": False, "msg": "Internal server error"}), 500

# **************************** CUSTOMER **************************** #
