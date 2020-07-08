from abc import abstractmethod, ABCMeta
from enum import Enum
from typing import Tuple

from .exceptions import (
    CognitoCreateUserException,
    CognitoAuthenticationException,
    CognitoConfirmUserException
)


class CognitoResponseType(Enum):
    """
    An enumeration representing different types of responses the Cognito IDP returns upon a particular request.
    """
    # Correct credentials provided for signin, no outstanding issues
    AUTHENTICATED = 1
    # Username or password incorrect
    INVALID_CREDENTIALS = 2
    # Temporary password used - password reset required
    TEMP_PWD_USED = 3
    # Password reset is required
    PWD_RESET_REQUIRED = 4
    # User account has not been confirmed
    UNCONFIRMED = 5
    # Unhandled exception
    ERROR = 6
    # User successfully created
    CREATED = 7
    # User already exists
    USER_EXISTS = 8
    # Incorrect password
    BAD_PASSWORD = 9
    # Missing information for signup
    INCOMPLETE_REQUEST = 10
    # account successfully confirmed
    CONFIRMED = 11
    # invalid confirmation token
    INVALID_TOKEN = 12
    # expired confirmation token
    EXPIRED_TOKEN = 13
    # too many failed attempts of operation
    FAILED_ATTEMPTS = 14
    # confirmation token resent succesfully
    RESENT = 15
    # confirmation token was not resent successfully
    DELIVERY_FAILED = 16
    # alias already exists in user pool
    ALIAS_EXISTS = 17


class CognitoResponse(object, metaclass=ABCMeta):
    """An abstract response from Cognito IDP"""

    def __init__(self, response_type: CognitoResponseType, error=None, message=None):
        """
        A response from the Cognito IDP service.

        :param response_type: The response type enum
        :param error: Message containing information about a request error
        :param message: Message containing general information about a response
        """
        self._response_type = response_type
        self.error = error
        self.message = message

    @abstractmethod
    def validate(self, throw=False):
        """
        Validates the Cognito response

        :return:
        """
        pass

    @property
    def response_type(self) -> CognitoResponseType:
        """
        The response type of the cognito request that produced this result object.

        :return: A cognito result type enumeration
        """
        return self._response_type


class CognitoConfirmUserResponse(CognitoResponse):
    """The result of a Cognito user confirmation request"""

    def __init__(self,
                 confirm_response_type: CognitoResponseType,
                 username=None,
                 message=None,
                 error=None):
        super(CognitoConfirmUserResponse, self).__init__(confirm_response_type, error=error, message=message)
        self.username = username

    def validate(self, throw=False):
        success = True
        if self.response_type != CognitoResponseType.CONFIRMED:
            if throw:
                raise CognitoConfirmUserException(self.error)
            success = False
        return success, self


class CognitoAuthenticationResponse(CognitoResponse):
    """The result of a Cogntio authentication request"""
    def __init__(self,
                 auth_response_type: CognitoResponseType,
                 username=None,
                 cognito_attributes=None,
                 challenge_params=None,
                 challenge_session_id=None,
                 access_token=None,
                 id_token=None,
                 refresh_token=None,
                 message=None,
                 error=None):
        super(CognitoAuthenticationResponse, self).__init__(auth_response_type, error=error, message=message)
        self.username = username
        self.cognito_attributes = cognito_attributes
        self.challenge_params = challenge_params
        self.challenge_session_id = challenge_session_id
        self.access_token = access_token
        self.id_token = id_token
        self.refresh_token = refresh_token

    @property
    def user_attributes(self):
        if self.cognito_attributes:
            user_attributes = {
                k: v if k != 'email_verified' else v.lower()
                for k, v in self.cognito_attributes.items()
            }
            return user_attributes

    def validate(self, throw=False) -> Tuple[bool, 'CognitoAuthenticationResponse']:
        success = True
        if self.response_type != CognitoResponseType.AUTHENTICATED:
            if throw:
                raise CognitoAuthenticationException(self.error)
            success = False
        return success, self


class CognitoCreateUserResponse(CognitoResponse):
    """The result of a Cogntio create-user request"""
    def __init__(self,
                 create_user_response_type: CognitoResponseType,
                 user_confirmed=False,
                 response_metadata=None,
                 user_sub=None,
                 message=None,
                 error=None):
        super(CognitoCreateUserResponse, self).__init__(create_user_response_type, error=error, message=message)
        self.user_confirmed = user_confirmed
        self.code_delivery_details = response_metadata
        self.user_sub = user_sub


    def validate(self, throw=False) -> Tuple[bool, 'CognitoCreateUserResponse']:
        sucess = True
        if self.response_type != CognitoResponseType.CREATED:
            if throw:
                raise CognitoCreateUserException(self.error)
            sucess = False
        return sucess, self


class CognitoResendResponse(CognitoResponse):
    """The result of a Cognito confirmation code resend request"""
    def __init__(self,
                 resend_response_type: CognitoResponseType,
                 username=None,
                 delivery_medium=None,
                 message=None,
                 error=None):
        super(CognitoResendResponse, self).__init__(resend_response_type, error=error, message=message)
        self.username = username
        self.delivery_medium = delivery_medium

    def validate(self, throw=False) -> Tuple[bool, 'CognitoResendResponse']:
        success = True
        if self.response_type != CognitoResponseType.RESENT:
            if throw:
                raise CognitoAuthenticationException(self.error)
        return success, self
