import base64
import hashlib
import hmac


def generate_secret_hash(username, app_client_id, app_client_secret_id):
    """
    Generates a secret hash requried for the AWS Cognito IDP API endpoints

    :param username: The username associated with the request
    :param app_client_id: The user pool app client ID
    :param app_client_secret_id: The user pool app secret ID
    :return: A base64 encoded secret hash
    """
    msg = username + app_client_id
    dig = hmac.new(app_client_secret_id.encode('utf-8'),
                   msg=msg.encode('utf-8'),
                   digestmod=hashlib.sha256).digest()
    return str(base64.b64encode(dig).decode())


class CognitoPoolRequest(object):
    """
    A Cognito User Pool request. Contains fields relevant to individual user
    singup, administrator-based account creation, and administrator-based account management
    """
    def __init__(self,
                 pool_id=None,
                 username=None,
                 email=None,
                 password=None,
                 confirm_password=None,
                 confirmation_code=None,
                 tmp_password=None):
        """
        Constructs a new Cognito User Pool request

        :param pool_id: user pool ID
        :param username: username associated witha s user in the user pool
        :param email: email associated with a user in the user pool
        :param password: the password value
        :param confirm_password: the confirm-password value
        :param confirmation_code: the confirmation code
        :param tmp_password: the temporary password associated with a user in the user pool
        """
        self.pool_id = pool_id
        self.username = username
        self.email = email
        self.password = password
        self.confirm_password = confirm_password
        self.confirmation_code = confirmation_code
        self.tmp_password = tmp_password

    def generate_secreate_hash(self, app_client_id, app_client_secret_id):
        """
        Generates a secret hash requried for the AWS Cognito IDP API endpoints, constucted
        using the username associated with this request object.

        :param app_client_id: The user pool app client ID
        :param app_client_secret_id: The user pool app secret ID
        :return: A base64 encoded secret hash
        """
        return generate_secret_hash(self.username, app_client_id, app_client_secret_id)

