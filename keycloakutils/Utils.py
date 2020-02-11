import requests


class Keycloak:
    def __init__(self, keycloak_url, realm, client_secret, client_id):
        self.__keycloak_url = str(keycloak_url)
        self.__realm = str(realm)
        self.__client_secret = str(client_secret)
        self.__client_id = str(client_id)

    def get_token(self, username, password):
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
        }

        payload = {
            'username': str(username),
            'password': str(password),
            'grant_type': 'password',
            'client_id': self.__client_id,
            'client_secret': self.__client_secret
        }

        response = requests.post(self.__keycloak_url + "/auth/realms/" + str(self.__realm) +
                                 "/protocol/openid-connect/token", data=payload, headers=headers)

        if response.status_code == 200:
            return {'status': True, 'response': {'access_token': response.json()['access_token']}}
        else:
            return {'status': False, 'msg': 'Error response code: ' + str(response.status_code),
                    'error_code': int(response.status_code)}

    def get_users(self, access_token, user_id=None, user_name=None, email=None):
        headers = {
            'Authorization': "Bearer " + access_token,
        }

        if user_id is None and user_name is None and email is None:
            response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users",
                                    headers=headers)
        else:
            if user_id is not None:
                response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) +
                                        "/users/" + str(user_id), headers=headers)
            elif email is not None:
                response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) +
                                        "/users?email=" + str(email), headers=headers)
            else:
                response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) +
                                        "/users?username=" + str(user_name), headers=headers)

        if response.status_code == 200:
            response_data = list()
            if user_id is not None:
                user = response.json()
                user_data = dict()
                if "firstName" in user.keys():
                    user_data["first_name"] = user['firstName']
                else:
                    user_data["first_name"] = ""

                if "lastName" in user.keys():
                    user_data["last_name"] = user['lastName']
                else:
                    user_data["last_name"] = ""

                if "attributes" in user.keys():
                    if "phone" in user["attributes"].keys():
                        if len(user["attributes"]["phone"]) > 0:
                            user_data["phone"] = user["attributes"]['phone'][0]
                        else:
                            user_data["phone"] = ""
                    else:
                        user_data["phone"] = ""
                else:
                    user_data["phone"] = ""

                if "email" in user.keys():
                    user_data["email"] = user['email']
                else:
                    user_data["email"] = ""

                user_data["username"] = user['username']
                user_data["id"] = user["id"]

                result = self.__get_user_groups(access_token, user["id"])
                if result['status']:
                    user_data["roles"] = result['response']
                else:
                    return {'status': False, 'msg': 'Error in \'get_users\'', 'error_code': 500}

                response_data.append(user_data)
            else:
                for user in response.json():
                    user_data = dict()
                    if "firstName" in user.keys():
                        user_data["first_name"] = user['firstName']
                    else:
                        user_data["first_name"] = ""

                    if "lastName" in user.keys():
                        user_data["last_name"] = user['lastName']
                    else:
                        user_data["last_name"] = ""

                    if "attributes" in user.keys():
                        if "phone" in user["attributes"].keys():
                            if len(user["attributes"]["phone"]) > 0:
                                user_data["phone"] = user["attributes"]['phone'][0]
                            else:
                                user_data["phone"] = ""
                        else:
                            user_data["phone"] = ""
                    else:
                        user_data["phone"] = ""

                    if "email" in user.keys():
                        user_data["email"] = user['email']
                    else:
                        user_data["email"] = ""

                    user_data["username"] = user['username']
                    user_data["id"] = user["id"]

                    result = self.__get_user_groups(access_token, user["id"])
                    if result['status']:
                        user_data["roles"] = result['response']
                    else:
                        return {'status': False, 'msg': 'Error in \'get_users\'', 'error_code': 500}

                    response_data.append(user_data)

            return {'status': True, 'response': response_data}
        else:
            return {'status': False, 'msg': 'Error in \'get_users\'', 'error_code': int(response.status_code)}

    # FOR PROFILE UPDATE REDIRECT TO http://dev.cyphercrypttech.com:8080/auth/realms/windo/account/

    def add_user(self, access_token, data):
        '''
        data body:
            {
                "first_name": string,
                "last_name": string,
                "phone": string,
                "email": string,
                "username": string,
                "password": string,
                "roles": [string, string, ...] # admin/backend/frontend/manager/customer
            }
        '''
        data = dict(data)
        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + access_token,
        }

        payload = '{"email": "' + data['email'] + '","emailVerified": true, "enabled": true, "firstName": "' \
                  + data['first_name'] + '", "lastName": "' + data['last_name'] + '", "requiredActions": [], ' \
                  '"username": "' + data['username'] + '", "credentials": [{"type": "password","value": "' \
                  + data['password'] + '","temporary": false}], "attributes": {"phone": ["' + data['phone'] + '"]}}'

        response = requests.post(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users",
                                 headers=headers, data=payload)

        if response.status_code == 201:
            user = self.get_users(access_token, user_name=data['username'])
            if user['status']:
                for role in data['roles']:
                    result = self.__add_user_to_group(access_token, str(dict(user['response'][0])['id']), role)
                    if not result['status']:
                        return {'status': False, 'msg': 'Unknown Error', 'error_code': 500}

                return {'status': True, 'response': {"user_id": str(dict(user['response'][0])['id'])}}
            else:
                return {'status': False, 'msg': 'Error in \'add_user\'', 'error_code': 500}
        else:
            return {'status': False, 'msg': 'Error in \'add_user\'', 'error_code': int(response.status_code)}

    def edit_user(self, access_token, user_id, new_data):
        '''
        data body:
            {
                "first_name": string,
                "last_name": string,
                "phone": string,
                "email": string,
                "roles": [string, string, ...] # admin/backend/frontend/manager/customer
            }
        '''

        data = dict()
        roles_to_delete = list()
        roles_to_add = list()

        old_user = self.get_users(access_token, user_id=user_id)
        if not old_user['status']:
            return {'status': False, 'msg': 'Error in \'edit_user\'', 'error_code': 500}
        old_user_data = dict(old_user['response'][0])

        new_data = dict(new_data)
        if "first_name" in list(new_data.keys()):
            if new_data["first_name"] != old_user_data["first_name"]:
                data["firstName"] = new_data["first_name"]

        if "last_name" in list(new_data.keys()):
            if new_data["last_name"] != old_user_data["last_name"]:
                data["lastName"] = new_data["last_name"]

        if "phone" in list(new_data.keys()):
            if new_data["phone"] != old_user_data["phone"]:
                data["attributes"] = dict()
                data["attributes"]["phone"] = [new_data["phone"]]

        if "email" in list(new_data.keys()):
            if new_data["email"] != old_user_data["email"]:
                data["email"] = new_data["email"]

        if "roles" in list(new_data.keys()):
            roles_to_add = list(set(new_data["roles"]) - set(old_user_data['roles']))
            roles_to_delete = list(set(old_user_data["roles"]) - set(new_data['roles']))

        if "email" in list(data.keys()):
            email_check = self.get_users(access_token, email=data["email"])
            if email_check['status']:
                if len(email_check["response"]) > 0:
                    return {'status': False, 'msg': 'email already registered', 'error_code': 409}
            else:
                return {'status': False, 'msg': 'Error in \'edit_user\'', 'error_code': 500}

        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + access_token,
        }

        response = requests.put(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                str(user_id), headers=headers, data=str(data).replace("'", '"'))

        if response.status_code == 204:
            for role in roles_to_add:
                result = self.__add_user_to_group(access_token, user_id, role)
                if not result['status']:
                    return {'status': False, 'msg': 'Error in \'edit_user\'', 'error_code': 500}

            for role in roles_to_delete:
                result = self.__delete_user_from_group(access_token, user_id, role)
                if not result['status']:
                    return {'status': False, 'msg': 'Error in \'edit_user\'', 'error_code': 500}

            return {'status': True, 'response': {"user_id": user_id}}
        else:
            return {'status': False, 'msg': 'Error in \'edit_user\'', 'error_code': int(response.status_code)}

    def reset_password(self, access_token, user_id, default_password):

        payload = '{"credentials": [{"type": "password","value": "' + str(default_password) + '","temporary": false}]}'
        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + access_token,
        }

        response = requests.put(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                str(user_id), headers=headers, data=payload)

        if response.status_code == 204:
            return {'status': True, 'response': {"user_id": user_id}}
        else:
            return {'status': False, 'msg': 'Error in \'reset_password\'', 'error_code': int(response.status_code)}

    def delete_user(self, access_token, user_id):
        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + access_token,
        }

        response = requests.delete(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                str(user_id), headers=headers)

        if response.status_code == 204:
            return {'status': True, 'response': {"user_id": user_id}}
        else:
            return {'status': False, 'msg': 'Error in \'delete_user\'', 'error_code': int(response.status_code)}

    def __get_group_id(self, access_token, group_name):
        headers = {
            'Authorization': "Bearer " + access_token,
        }

        response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) +
                                "/groups?search=" + str(group_name), headers=headers)

        if response.status_code == 200:
            return {'status': True, 'response': {"group_id": response.json()[0]['id']}}
        else:
            return {'status': False, 'msg': 'Error response code: ' + str(response.status_code),
                    'error_code': int(response.status_code)}

    def __add_user_to_group(self, access_token, user_id, group_name):
        group = self.__get_group_id(access_token, group_name)

        if group['status']:
            group_id = group['response']['group_id']
        else:
            return {'status': False, 'msg': 'Unknown Error',
                    'error_code': 500}

        headers = {
            'Authorization': "Bearer " + access_token,
        }

        response = requests.put(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                str(user_id) + "/groups/" + str(group_id),
                                headers=headers)

        if response.status_code == 204:
            return {'status': True}
        else:
            return {'status': False, 'msg': 'Error response code: ' + str(response.status_code),
                    'error_code': int(response.status_code)}

    def __get_user_groups(self, access_token, user_id):
        headers = {
            'Authorization': "Bearer " + access_token,
        }

        response = requests.get(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                str(user_id) + "/groups", headers=headers)

        if response.status_code == 200:
            response_data = list()
            for res in response.json():
                response_data.append(res['name'])

            return {'status': True, 'response': response_data}
        else:
            return {'status': False, 'msg': 'Error in __get_user_groups', 'error_code': int(response.status_code)}

    def __delete_user_from_group(self, access_token, user_id, group_name):
        group = self.__get_group_id(access_token, group_name)

        if group['status']:
            group_id = group['response']['group_id']
        else:
            return {'status': False, 'msg': 'Unknown Error',
                    'error_code': 500}

        headers = {
            'Authorization': "Bearer " + access_token,
        }

        response = requests.delete(self.__keycloak_url + "/auth/admin/realms/" + str(self.__realm) + "/users/" +
                                   str(user_id) + "/groups/" + str(group_id), headers=headers)

        if response.status_code == 204:
            return {'status': True}
        else:
            return {'status': False, 'msg': 'Error response code: ' + str(response.status_code),
                    'error_code': int(response.status_code)}
