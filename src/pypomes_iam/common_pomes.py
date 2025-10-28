import json
import requests
import secrets
import string
import sys
from cachetools import Cache
from datetime import datetime
from flask import Request
from logging import Logger
from pypomes_core import TZ_LOCAL, exc_format
from typing import Any

# registry structure:
# {
#    "client-id": <str>,
#    "client-secret": <str>,
#    "client-timeout": <int>,
#    "public_key": <str>,
#    "key-lifetime": <int>,
#    "key-expiration": <int>,
#    "base-url": <str>,
#    "callback-url": <str>,
#    "safe-cache": <FIFOCache>
# }
# data in "safe-cache":
# {
#    "users": {
#       "<user-id>": {
#         "access-token": <str>
#         "refresh-token": <str>
#         "access-expiration": <timestamp>,
#         "login-expiration": <timestamp>,   <-- transient
#         "login-id": <str>,                 <-- transient
#         "oauth-scope": <str>               <-- optional
#       }
#    }
# }


def _service_callback(registry: dict[str, Any],
                      args: dict[str, Any],
                      errors: list[str],
                      logger: Logger | None) -> tuple[str, str]:
    """
    Entry point for the callback from JusBR on authentication operation.

    :param registry: the registry holding the authentication data
    :param args: the arguments passed when requesting the service
    :param errors: incidental errors
    :param logger: optional logger
    """
    from .token_pomes import token_validate

    # initialize the return variable
    result: tuple[str, str] | None = None

    # retrieve the users authentication data
    cache: Cache = registry["safe-cache"]
    users: dict[str, dict[str, Any]] = cache.get("users")

    # validate the OAuth2 state
    oauth_state: str = args.get("state")
    user_data: dict[str, Any] | None = None
    if oauth_state:
        for user, data in users.items():
            if user == oauth_state:
                user_data = data
                break

    # exchange 'code' for the token
    if user_data:
        users.pop(oauth_state)
        code: str = args.get("code")
        body_data: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": registry.get("callback-url"),
        }
        token = _post_for_token(registry=registry,
                                user_data=user_data,
                                body_data=body_data,
                                errors=errors,
                                logger=logger)
        # retrieve the token's claims
        if not errors:
            public_key: bytes = _get_public_key(registry=registry,
                                                logger=logger)
            token_claims: dict[str, dict[str, Any]] = token_validate(token=token,
                                                                     issuer=registry["base-url"],
                                                                     public_key=public_key,
                                                                     errors=errors,
                                                                     logger=logger)
            if not errors:
                token_user: str = token_claims["payload"].get("preferred_username")
                if token_user == oauth_state:
                    users[token_user] = user_data
                    result = (token_user, token)
                else:
                    errors.append(f"Token was issued to user '{token_user}'")
    else:
        msg: str = "Unknown OAuth2 code received"
        if _get_login_timeout(registry=registry):
            msg += " - possible operation timeout"
        errors.append(msg)

    return result


def _service_login(registry: dict[str, Any],
                   args: dict[str, Any],
                   logger: Logger | None) -> str:
    """
    Build the callback URL for redirecting the request to the IAM's authentication page.

    :param registry: the registry holding the authentication data
    :param args: the arguments passed when requesting the service
    :param logger: optional logger
    :return: the callback URL, with the appropriate parameters
    """

    # retrieve user data
    oauth_state: str = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))

    # build the user data
    #   ('oauth_state' is a randomly-generated string, thus 'user_data' is always a new entry)
    user_data: dict[str, Any] = _get_user_data(registry=registry,
                                               user_id=oauth_state,
                                               logger=logger)
    user_id: str = args.get("user-id") or args.get("user_id") or args.get("login")
    user_data["login-id"] = user_id
    timeout: int = _get_login_timeout(registry=registry)
    user_data["login-expiration"] = int(datetime.now(tz=TZ_LOCAL).timestamp()) + timeout if timeout else None

    # build the redirect url
    result: str = (f"{registry["base-url"]}/protocol/openid-connect/auth?response_type=code"
                   f"&client_id={registry["client-id"]}"
                   f"&redirect_uri={registry["callback-url"]}"
                   f"&state={oauth_state}")
    scope: str = _get_user_scope(registry=registry,
                                 user_id=user_id)
    if scope:
        user_data["oauth-scope"] = scope
        result += f"&scope={scope}"

    # logout the user
    _service_logout(registry=registry,
                    args=args,
                    logger=logger)
    return result


def _service_logout(registry: dict[str, Any],
                    args: dict[str, Any],
                    logger: Logger | None) -> None:
    """
    Remove all data associating *user_id* from *registry*.

    :param registry: the registry holding the authentication data
    :param args: the arguments passed when requesting the service
    :param logger: optional logger
    """
    # remove the user data
    user_id: str = args.get("user-id") or args.get("login")
    if user_id:
        cache: Cache = registry["safe-cache"]
        users: dict[str, dict[str, Any]] = cache.get("users")
        if user_id in users:
            users.pop(user_id)
            if logger:
                logger.debug(msg=f"User '{user_id}' removed from the registry")


def _service_token(registry: dict[str, Any],
                   args: dict[str, Any],
                   errors: list[str] = None,
                   logger: Logger = None) -> str:
    """
    Retrieve the authentication token for user *user_id*.

    :param registry: the registry holding the authentication data
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token for *user_id*, or *None* if error
    """
    # initialize the return variable
    result: str | None = None

    user_id: str = args.get("user-id") or args.get("user_id") or args.get("login")
    user_data: dict[str, Any] = _get_user_data(registry=registry,
                                               user_id=user_id,
                                               logger=logger)
    token: str = user_data["access-token"]
    if token:
        access_expiration: int = user_data.get("access-expiration")
        now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
        if now < access_expiration:
            result = token
        else:
            # access token has expired
            refresh_token: str = user_data["refresh-token"]
            if refresh_token:
                body_data: dict[str, str] = {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }
                result = _post_for_token(registry=registry,
                                         user_data=user_data,
                                         body_data=body_data,
                                         errors=errors,
                                         logger=logger)

    elif logger or isinstance(errors, list):
        err_msg: str = f"User '{user_id}' not authenticated"
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)

    return result


def _get_public_key(registry: dict[str, Any],
                    logger: Logger | None) -> bytes:
    """
    Obtain the public key used by the *IAM* to sign the authentication tokens.

    The public key is saved in *registry*.

    :param registry: the registry holding the authentication data
    :return: the public key, in *DER* format
    """
    from pypomes_crypto import crypto_jwk_convert

    # initialize the return variable
    result: bytes | None = None

    now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
    if now > registry["key-expiration"]:
        # obtain a new public key
        url: str = f"{registry["base-url"]}/protocol/openid-connect/certs"
        if logger:
            logger.debug(msg=f"GET '{url}'")
        response: requests.Response = requests.get(url=url)
        if response.status_code == 200:
            # request succeeded
            if logger:
                logger.debug(msg=f"GET success, status {response.status_code}")
            reply: dict[str, Any] = response.json()
            result = crypto_jwk_convert(jwk=reply["keys"][0],
                                        fmt="DER")
            registry["public-key"] = result
            duration: int = registry["key-lifetime"] or 0
            registry["key-expiration"] = now + duration
        elif logger:
            msg: str = f"GET failure, status {response.status_code}, reason '{response.reason}'"
            if hasattr(response, "content") and response.content:
                msg += f", content '{response.content}'"
            logger.error(msg=msg)
    else:
        result = registry["public-key"]

    return result


def _get_login_timeout(registry: dict[str, Any]) -> int | None:
    """
    Retrieve from *registry* the timeout currently applicable for the login operation.

    :param registry: the registry holding the authentication data
    :return: the current login timeout, or *None* if none has been set.
    """
    timeout: int = registry.get("client-timeout")
    return timeout if isinstance(timeout, int) and timeout > 0 else None


def _get_user_data(registry: dict[str, Any],
                   user_id: str,
                   logger: Logger | None) -> dict[str, Any]:
    """
    Retrieve the data for *user_id* from *registry*.

    If an entry is not found for *user_id* in the registry, it is created.
    It will remain there until the user is logged out.

    :param registry: the registry holding the authentication data
    :return: the data for *user_id* in the registry
    """
    cache: Cache = registry["safe-cache"]
    users: dict[str, dict[str, Any]] = cache.get("users")
    result: dict[str, Any] = users.get(user_id)
    if not result:
        result = {
            "access-token": None,
            "refresh-token": None,
            "access-expiration": int(datetime.now(tz=TZ_LOCAL).timestamp())
        }
        users[user_id] = result
        if logger:
            logger.debug(msg=f"Entry for user '{user_id}' added to the registry")
    elif logger:
        logger.debug(msg=f"Entry for user '{user_id}' obtained from the registry")

    return result


def _get_user_scope(registry: dict[str, Any],
                    user_id: str) -> str | None:
    """
    Retrieve the OAuth2 scope associated with *user_id*.

    :param registry: the registry holding the authentication data
    :param user_id:
    :return: the OAuth2 scope associated with *user_id*, or *None* if it does not exist
    """
    # initialize the return variable
    result: str | None = None

    if user_id:
        cache: Cache = registry["safe-cache"]
        users: dict[str, dict[str, Any]] = cache.get("users")
        if user_id in users:
            result = users[user_id].get("oauth2-scope")

    return result


def _post_for_token(registry: dict[str, Any],
                    user_data: dict[str, Any],
                    body_data: dict[str, Any],
                    errors: list[str] | None,
                    logger: Logger | None) -> str | None:
    """
    Send a POST request to obtain the authentication token data, and return the access token.

    For token exchange, *body_data* will have the attributes
        - "grant_type": "authorization_code"
        - "code": <16-character-random-code>
        - "redirect_uri": <callback-url>
    For token refresh, *body_data* will have the attributes
        - "grant_type": "refresh_token"
        - "refresh_token": <current-refresh-token>

    If the operation is successful, the token data is stored in the registry.
    Otherwise, *errors* will contain the appropriate error message.

    :param registry: the registry holding the authentication data
    :param user_data: the user's data in the registry
    :param body_data: the data to send in the body of the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the access token obtained, or *None* if error
    """
    # initialize the return variable
    result: str | None = None

    # complete the data to send in body of request
    body_data["client_id"] = registry["client-id"]
    client_secret: str = registry["client-secret"]
    if client_secret:
        body_data["client_secret"] = client_secret

    # obtain the token
    err_msg: str | None = None
    url: str = registry["base-url"] + "/protocol/openid-connect/token"
    now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
    if logger:
        logger.debug(msg=f"POST '{url}', data {json.dumps(obj=body_data,
                                                          ensure_ascii=False)}")
    try:
        # typical return on a token request:
        # {
        #   "token_type": "Bearer",
        #   "access_token": <str>,
        #   "expires_in": <number-of-seconds>,
        #   "refresh_token": <str>
        # }
        response: requests.Response = requests.post(url=url,
                                                    data=body_data)
        if response.status_code == 200:
            # request succeeded
            if logger:
                logger.debug(msg=f"POST success, status {response.status_code}")
            reply: dict[str, Any] = response.json()
            result = reply.get("access_token")
            user_data["access-token"] = result
            # on token refresh, keep current refresh token if a new one is not provided
            user_data["refresh-token"] = reply.get("refresh_token") or body_data.get("refresh_token")
            user_data["access-expiration"] = now + reply.get("expires_in")
        else:
            # request resulted in error
            err_msg = f"POST failure, status {response.status_code}, reason '{response.reason}'"
            if hasattr(response, "content") and response.content:
                err_msg += f", content '{response.content}'"
            if response.status_code == 400 and body_data.get("grant_type") == "refresh_token":
                # refresh token is no longer valid
                user_data["refresh-token"] = None
    except Exception as e:
        # the operation raised an exception
        err_msg = exc_format(exc=e,
                             exc_info=sys.exc_info())
        err_msg = f"POST '{url}': error '{err_msg}'"

    if err_msg:
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)

    return result


def _log_init(request: Request) -> str:
    """
    Build the messages for logging the request entry.

    :param request: the Request object
    :return: the log message
    """

    params: str = json.dumps(obj=request.args,
                             ensure_ascii=False)
    return f"Request {request.method}:{request.path}, params {params}"
