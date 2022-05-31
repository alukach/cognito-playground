"""
This demonstrates how an API can be authenticated against Cognito.
"""

import logging
from functools import lru_cache

from authlib.jose import JsonWebToken, JsonWebKey, KeySet, JWTClaims, errors
from cachetools import cached, TTLCache
from fastapi import FastAPI, Depends, HTTPException, security
import requests
import pydantic

logger = logging.getLogger(__name__)

token_scheme = security.HTTPBearer()


class Settings(pydantic.BaseSettings):
    cognito_user_pool_id: str

    class Config:
        env_file = ".env"

    @property
    def jwks_url(self):
        """
        Build JWKS url
        """
        pool_id = self.cognito_user_pool_id
        region = pool_id.split("_")[0]
        return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"


@lru_cache()
def get_settings() -> Settings:
    """
    Load settings (once per app lifetime)
    """
    return Settings()


def get_jwks_url(settings: Settings = Depends(get_settings)) -> str:
    """
    Get JWKS url
    """
    return settings.jwks_url


@cached(TTLCache(maxsize=1, ttl=3600))
def get_jwks(url: str = Depends(get_jwks_url)) -> KeySet:
    """
    Get cached or new JWKS. Cognito does not seem to rotate keys, however to be safe we
    are lazy-loading new credentials every hour.
    """
    logger.info("Fetching JWKS from %s", url)
    with requests.get(url) as response:
        response.raise_for_status()
        return JsonWebKey.import_key_set(response.json())


def decode_token(
    token: security.HTTPAuthorizationCredentials = Depends(token_scheme),
    jwks: KeySet = Depends(get_jwks),
) -> JWTClaims:
    """
    Validate & decode JWT.
    """
    try:
        return JsonWebToken().decode(s=token.credentials, key=jwks)
    except errors.JoseError:
        logger.exception("Unable to decode token")
        raise HTTPException(status_code=403, detail="Bad auth token")


app = FastAPI(docs_url="/")


@app.get("/who-am-i")
def who_am_i(claims=Depends(decode_token)) -> str:
    """
    Return claims for the provided JWT
    """
    return claims


@app.get("/auth-test", dependencies=[Depends(decode_token)])
def auth_test() -> bool:
    """
    Require auth but not use it as a dependency
    """
    return True
