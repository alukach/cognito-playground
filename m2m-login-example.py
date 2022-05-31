"""
This demonstrates how a service can authenticate with Cognito via
the client_credentials flow.
"""

import requests
from pydantic import BaseModel, BaseSettings, HttpUrl


class Config(BaseSettings):
    cognito_domain: HttpUrl
    client_id: str
    client_secret: str

    class Config:
        env_file = ".env"


class Credentials(BaseModel):
    access_token: str
    expires_in: int
    token_type: str


def get_token(domain: str, client_id: str, client_secret: str):
    response = requests.post(
        f"{domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=(client_id, client_secret),
        data={"grant_type": "client_credentials", "scope": " ".join(["some_api/Test"])},
    )
    try:
        response.raise_for_status()
    except Exception:
        print(response.text)
        raise

    return Credentials.parse_obj(response.json())


if __name__ == "__main__":
    settings = Config()
    token = get_token(
        domain=settings.cognito_domain,
        client_id=settings.client_id,
        client_secret=settings.client_secret,
    )
    print(token.json())
