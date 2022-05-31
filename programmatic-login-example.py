#!/usr/bin/env python
"""
The represents how a user can authenticate with a Cogntio application
within an interactive Python environment (e.g. Python Notebook)
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional
import getpass
import json
import logging

import boto3
import dotenv
from pydantic import BaseSettings, Field

if TYPE_CHECKING:
    from mypy_boto3_cognito_idp.client import CognitoIdentityProviderClient
    from mypy_boto3_cognito_idp.type_defs import InitiateAuthResponseTypeDef


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)


class ChallengeType(str, Enum):
    SMS_MFA = "SMS_MFA"
    SOFTWARE_TOKEN_MFA = "SOFTWARE_TOKEN_MFA"
    SELECT_MFA_TYPE = "SELECT_MFA_TYPE"
    MFA_SETUP = "MFA_SETUP"
    PASSWORD_VERIFIER = "PASSWORD_VERIFIER"
    CUSTOM_CHALLENGE = "CUSTOM_CHALLENGE"
    DEVICE_SRP_AUTH = "DEVICE_SRP_AUTH"
    DEVICE_PASSWORD_VERIFIER = "DEVICE_PASSWORD_VERIFIER"
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"


class AuthFailure(Exception):
    ...


class VedaAuthClient(BaseSettings):
    # username can be either email address or sub
    username: str = Field(default_factory=lambda: input("Username: "))
    # password
    password: str = Field(default_factory=getpass.getpass, repr=False)
    # cognito app client identifier
    app_client_id: str = Field(
        default_factory=lambda: input("Cognito App Client ID: "), repr=False
    )

    # Manually provide an access token to skip logging-in when the client is initiated.
    access_token: Optional[str] = None

    # Controls whether a we should automatically attempt to resolve challenges
    resolve_challenges: bool = True

    class Config:
        env_file = ".env"

    @property
    def cognito_client(self) -> "CognitoIdentityProviderClient":
        return boto3.client("cognito-idp", region_name="us-east-1")

    def login(self) -> "InitiateAuthResponseTypeDef":
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": self.username, "PASSWORD": self.password},
            )
        except self.cognito_client.exceptions.PasswordResetRequiredException:
            if not self.resolve_challenges:
                raise

            # print("Password reset required. Check your email for a confirmation code.")
            return self._resolve_password_reset()

        if challenge_name := response.get("ChallengeName"):
            if self.resolve_challenges:
                response = self._resolve_auth_challenge(
                    ChallengeName=challenge_name, Session=response["Session"]
                )
            else:
                raise AuthFailure(
                    f"Received auth challenge {challenge_name}. Aborting."
                )

        if "AuthenticationResult" not in response:
            raise AuthFailure(f"Failed to authenticate. Response: \n{response}")

        self.access_token = response["AuthenticationResult"]["AccessToken"]
        return response

    def _resolve_auth_challenge(
        self,
        ChallengeName: ChallengeType,
        Session: str,
    ) -> "InitiateAuthResponseTypeDef":
        """
        If Cognito responds with an auth challenge, prompt user to submit information
        necessary to complete login.
        """
        ChallengeResponse = {"USERNAME": self.username}
        if ChallengeName == ChallengeType.NEW_PASSWORD_REQUIRED:
            ChallengeResponse["NEW_PASSWORD"] = getpass.getpass(
                "A new password is required. Please provide a new password: "
            )
        elif ChallengeName == ChallengeType.SMS_MFA:
            ChallengeResponse["SMS_MFA_CODE"] = input(
                "Please provide the code sent to you via SMS: "
            )
        elif ChallengeName == ChallengeType.SMS_MFA:
            ChallengeResponse["SMS_MFA_CODE"] = input(
                "Please provide the code sent to you via SMS: "
            )
        else:
            raise AuthFailure(
                f"Unexpected auth challenge encountered: '{ChallengeName}'. "
                "Unable to automatically resolve issue."
            )

        response = self.cognito_client.respond_to_auth_challenge(
            ClientId=self.app_client_id,
            Session=Session,
            ChallengeName=ChallengeName,
            ChallengeResponses=ChallengeResponse,
        )

        if ChallengeName == ChallengeType.NEW_PASSWORD_REQUIRED:
            # TODO: Saving password on client is probably a security risk/anti-pattern.
            self.password = ChallengeResponse["NEW_PASSWORD"]

        return response

    def _init_password_reset(self):
        self.cognito_client.resend_confirmation_code(
            ClientId=self.app_client_id, Username=self.username
        )

    def _resolve_password_reset(
        self, confirmation_code=None, new_password=None
    ) -> "InitiateAuthResponseTypeDef":
        """
        Complete password reset flow.
        """
        confirmation_code = confirmation_code or input("Confirmation code: ")
        new_password = new_password or getpass.getpass("New password: ")
        response = self.cognito_client.confirm_forgot_password(
            ClientId=self.app_client_id,
            Username=self.username,
            ConfirmationCode=confirmation_code,
            Password=new_password,
        )

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise AuthFailure(f"Failed to reset password. Response: \n{response}")

        logger.info("Successfully set password.")

        self.password = new_password

        return self.login()

    def get_user(self):
        return self.cognito_client.get_user(AccessToken=self.access_token)


if __name__ == "__main__":
    client = VedaAuthClient()
    client.login()
    print(client.access_token)
    print(json.dumps(client.get_user()))
