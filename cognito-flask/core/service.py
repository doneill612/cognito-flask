import boto3
import botocore.exceptions

from .response import (
    CognitoResponseType,
    CognitoAuthenticationResponse,
    CognitoCreateUserResponse,
    CognitoConfirmUserResponse,
    CognitoResendResponse
)

from .request import CognitoPoolRequest


class CognitoAuthenticationService(object):
    """
    A site authentication service that authenticates users with AWS Cogntio.
    """
    def __init__(self, aws_profile_name, aws_region, pool_id, client_id, client_secret_id):
        """
        Constructs a new Cogntio authentication service.
        """
        self._user_pool_id = pool_id
        self._app_client_id = client_id
        self._app_secret_id = client_secret_id

        session = boto3.session.Session(profile_name=aws_profile_name)
        self._client = session.client('cognito-idp', region_name=aws_region)

    def admin_get_user(self, request: CognitoPoolRequest) -> CognitoAuthenticationResponse:
        """
        Attempts to get a user from the user pool using administrator pool access.

        :param request: The request information
        :return: A CognitoAuthenticationResult
        """
        try:
            response = self._client.admin_get_user(
                UserPoolId=self._user_pool_id,
                Username=request.username
            )
            return CognitoAuthenticationResponse(
                auth_response_type=CognitoResponseType.AUTHENTICATED,
                username=response['Username']
                #TODO pass current user token consistently across all flask login get-user requests, to maintain
                # synchronicity of token during site navigation
            )
        except botocore.exceptions.ClientError as aws_exception:
            error_code = aws_exception.response['Error']['Code']
            if error_code == 'UserNotFoundException':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.INVALID_CREDENTIALS,
                    error='User not found.'
                )
            else:
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.ERROR,
                    error=f'An unexpected error occured during authentication. Please '
                          f'communicate the following to a site administrator.\n {type(aws_exception)}: {aws_exception}'
                )

        except Exception as exception:
            return CognitoAuthenticationResponse(
                auth_response_type=CognitoResponseType.ERROR,
                error=f'An unexpected error occured during authentication. Please '
                      f'communicate the following to a site administrator.\n {type(exception)}: {exception}'
            )

    def authenticate(self, request: CognitoPoolRequest) -> CognitoAuthenticationResponse:
        """
        Attempts to authenticate user credentials with the Cognito Identity Provider service.

        :param request: The request to authenticate
        :return: An authentication result object
        """
        try:
            auth_params = {
                'USERNAME': request.username,
                'PASSWORD': request.password,
                'SECRET_HASH': request.generate_secret_hash(self._app_client_id, self._app_secret_id)
            }
            initiate_response = self._client.admin_initiate_auth(
                UserPoolId=self._user_pool_id,
                ClientId=self._app_client_id,
                AuthParameters=auth_params,
                AuthFlow='ADMIN_NO_SRP_AUTH'
            )

            if 'ChallengeName' in initiate_response and initiate_response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.TEMP_PWD_USED,
                    challenge_params=initiate_response['ChallengeParameters'],
                    challenge_session_id=initiate_response['Session'],
                    error='You have provided a temporary password, and must now reset your account password.'
                )

            id_token = initiate_response['AuthenticationResult']['IdToken']
            access_token = initiate_response['AuthenticationResult']['AccessToken']
            refresh_token = initiate_response['AuthenticationResult']['RefreshToken']

            get_user_response = self._client.admin_get_user(
                UserPoolId=self._user_pool_id,
                Username=request.username
            )
            username = get_user_response['Username']
            cognito_attributes = get_user_response['UserAttributes']

            return CognitoAuthenticationResponse(
                auth_response_type=CognitoResponseType.AUTHENTICATED,
                username=username,
                cognito_attributes=cognito_attributes,
                access_token=access_token,
                id_token=id_token,
                refresh_token=refresh_token,
                message=f'Welcome, {username}!'
            )

        except botocore.exceptions.ClientError as aws_exception:
            error_code = aws_exception.response['Error']['Code']
            if error_code == 'PasswordResetRequiredException':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.PWD_RESET_REQUIRED,
                    error='You must reset your password.'
                )
            elif error_code == 'NotAuthorizedException':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.INVALID_CREDENTIALS,
                    error='The username or password you provided was incorrect.'
                )
            elif error_code == 'UserNotFoundException':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.INVALID_CREDENTIALS,
                    error='The username provided did not match any user in the directory.'
                )
            elif error_code == 'UserNotConfirmedException':
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.UNCONFIRMED,
                    username=request.username,
                    error='Your account still needs to be confirmed! '
                          'Check your email for your supplied confirmation code.'
                )

            else:
                return CognitoAuthenticationResponse(
                    auth_response_type=CognitoResponseType.ERROR,
                    error=f'An unexpected error occured during authentication. Please '
                          f'communicate the following to a site administrator.\n {type(aws_exception)}: {aws_exception}'
                )
        except Exception as exception:
            return CognitoAuthenticationResponse(
                auth_response_type=CognitoResponseType.ERROR,
                error=f'An unexpected error occured during authentication. Please '
                      f'communicate the following to a site administrator.\n {type(exception)}: {exception}'
            )

    def create_user(self, request: CognitoPoolRequest) -> CognitoCreateUserResponse:
        """
        Attempts to create a new, unconfirmed user account

        :param request: The request for user creation
        :return: A user creation result object
        """
        if not request.username or not request.email or not request.password:
            return CognitoCreateUserResponse(
                create_user_response_type=CognitoResponseType.INCOMPLETE_REQUEST,
                error='A username, email, and password must be provided to create a new account.'
            )

        if request.password != request.confirm_password:
            return CognitoCreateUserResponse(
                create_user_response_type=CognitoResponseType.BAD_PASSWORD,
                error='The supplied passwords do not match.'
            )

        try:
            user_attributes = [{
                'Name': 'email',
                'Value': request.email
            }]
            signup_response = self._client.sign_up(
                ClientId=self._app_client_id,
                SecretHash=request.generate_secret_hash( self._app_client_id, self._app_secret_id),
                Username=request.username,
                Password=request.password,
                UserAttributes=user_attributes
            )
            return CognitoCreateUserResponse(
                create_user_response_type=CognitoResponseType.CREATED,
                user_confirmed=signup_response['UserConfirmed'],
                response_metadata=signup_response['ResponseMetadata'],
                user_sub=signup_response['UserSub'],
                message=f'A confirmation message has been sent to {request.email}'
            )

        except botocore.exceptions.ClientError as aws_exception:
            error_code = aws_exception.response['Error']['Code']
            if error_code == 'UsernameExistsException':
                return CognitoCreateUserResponse(
                    create_user_response_type=CognitoResponseType.USER_EXISTS,
                    error='A user with that username or email already exists.'
                )
            elif error_code == 'InvalidPasswordException':
                return CognitoCreateUserResponse(
                    create_user_response_type=CognitoResponseType.BAD_PASSWORD,
                    error='Passwords must be a minimum of 8 characters, with at least '
                          'one upper-case letter, one lower-case letter, one numeric character, '
                          'and one special character.'
                )
            elif error_code == 'InvalidParameterException':
                return CognitoCreateUserResponse(
                    create_user_response_type=CognitoResponseType.INVALID_CREDENTIALS,
                    error='You must supply a valid email address to create an account.'
                )
            elif error_code == 'ParamValidationError':
                return CognitoCreateUserResponse(
                    create_user_response_type=CognitoResponseType.INVALID_CREDENTIALS,
                    error='Passwords must be a minimum of 8 characters, with at least '
                          'one upper-case letter, one lower-case letter, one numeric character, '
                          'and one special character.'
                    )
            else:
                return CognitoCreateUserResponse(
                    create_user_response_type=CognitoResponseType.ERROR,
                    error=f'An unexpected error occured during account creation. Please '
                          f'communicate the following to a site administrator.\n {type(aws_exception)}: {aws_exception}'
                )
        except Exception as exception:
            return CognitoCreateUserResponse(
                create_user_response_type=CognitoResponseType.ERROR,
                error=f'An unexpected error occured during account creation. Please '
                      f'communicate the following to a site administrator.\n {type(exception)}: {exception}'
            )

    def confirm_user(self, request: CognitoPoolRequest) -> CognitoConfirmUserResponse:
        """Attempts to confirm a newly-created user account"""
        try:
            self._client.confirm_sign_up(
                ClientId=self._app_client_id,
                SecretHash=request.generate_secret_hash(self._app_client_id, self._app_secret_id),
                Username=request.username,
                ConfirmationCode=request.confirmation_code
            )
            return CognitoConfirmUserResponse(
                confirm_response_type=CognitoResponseType.CONFIRMED,
                username=request.username,
                message='Your account was successfully confirmed! You may now login.'
            )
        except botocore.exceptions.ClientError as aws_exception:
            error_code = aws_exception.response['Error']['Code']
            if error_code == 'CodeMismatchException':
                return CognitoConfirmUserResponse(
                    confirm_response_type=CognitoResponseType.INVALID_TOKEN,
                    error='The confirmation code you entered was not correct.'
                )
            elif error_code == 'TooManyFailedAttemptsException':
                return CognitoConfirmUserResponse(
                    confirm_response_type=CognitoResponseType.FAILED_ATTEMPTS,
                    error='You have entered your confirmation code incorrectly too many times. '
                          'Request that a new code be sent.'
                )
            elif error_code == 'ExpiredCodeException':
                return CognitoConfirmUserResponse(
                    confirm_response_type=CognitoResponseType.EXPIRED_TOKEN,
                    error='Your confirmation code has expired. Request that a new code be sent.'
                )
            elif error_code == 'AliasExistsException':
                return CognitoConfirmUserResponse(
                    confirm_response_type=CognitoResponseType.ALIAS_EXISTS,
                    error='An account with the requested email alias already exists. Please contact an '
                          'administrator to delete this request.'
                )
            else:
                return CognitoConfirmUserResponse(
                    confirm_response_type=CognitoResponseType.ERROR,
                    error=f'An unexpected error occured during account creation. Please '
                          f'communicate the following to a site administrator.\n {type(aws_exception)}: {aws_exception}'
                )
        except Exception as exception:
            return CognitoConfirmUserResponse(
                confirm_response_type=CognitoResponseType.ERROR,
                error=f'An unexpected error occured during account confirmation. Please '
                      f'communicate the following to a site administrator.\n {type(exception)}: {exception}'
            )

    def resend_confirmation_code(self, request: CognitoPoolRequest) -> CognitoResendResponse:
        """
        Attempts to resend a verification code for the specified, unconfirmed user account

        :param request: The request containing the user information for which to resend an account confirmation code
        :return: A Cognito Response
        """
        try:
            resend_response = self._client.resend_confirmation(
                ClientId=self._app_client_id,
                Username=request.username,
                SecretHash=request.generate_secret_hash(self._app_client_id, self._app_secret_id)
            )

            return CognitoResendResponse(
                resend_response_type=CognitoResponseType.RESENT,
                username=request.username,
                delivery_medium=resend_response['CodeDeliveryDetails']['DeliveryMedium'],
                message='A new confirmation code has been sent to your registered email.'
            )

        except botocore.exceptions.ClientError as aws_exception:
            error_code = aws_exception.response['Error']['Code']
            if error_code == 'CodeDeliveryFailureException':
                return CognitoResendResponse(
                    resend_response_type=CognitoResponseType.DELIVERY_FAILED,
                    username=request.username,
                    error=f'Your new confirmation code could not be sent. Please report '
                          f'the following message to a site administrator: {type(aws_exception)} : {aws_exception}'
                )
            else:
                return CognitoResendResponse(
                    resend_response_type=CognitoResponseType.ERROR,
                    username=request.username,
                    error=f'An unexpected error occured while resending the confirmation code. Please '
                          f'communicate the following to a site administrator.\n {type(aws_exception)}: {aws_exception}'
                )
        except Exception as exception:
            return CognitoResendResponse(
                resend_response_type=CognitoResponseType.ERROR,
                username=request.username,
                error=f'An unexpected error occured while resending the confirmation code. Please '
                      f'communicate the following to a site administrator.\n {type(exception)}: {exception}'
            )