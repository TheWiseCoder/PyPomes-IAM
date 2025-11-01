import json
import requests
import secrets
import string
import sys
from datetime import datetime
from logging import Logger
from pypomes_core import TZ_LOCAL, exc_format
from typing import Any

from .iam_common import (
    IamServer, IamParam, UserParam, _iam_lock,
    _get_iam_users, _get_iam_registry,  # _get_public_key,
    _get_login_timeout, _get_user_data
)
from .token_pomes import token_get_claims, token_validate


def action_login(iam_server: IamServer,
                 args: dict[str, Any],
                 errors: list[str] = None,
                 logger: Logger = None) -> str:
    """
    Build the URL for redirecting the request to *iam_server*'s authentication page.

    These are the expected attributes in *args*:
        - user-id: optional, identifies the reference user (alias: 'login')
        - redirect-uri: a parameter to be added to the query part of the returned URL

    If provided, the user identification will be validated against the authorization data
    returned by *iam_server* upon login. On success, the appropriate URL for invoking
    the IAM server's authentication page is returned.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the callback URL, with the appropriate parameters, of *None* if error
    """
    # initialize the return variable
    result: str | None = None

    # obtain the optional user's identification
    user_id: str = args.get("user-id") or args.get("login")

    # build the user data
    # ('oauth_state' is a randomly-generated string, thus 'user_data' is always a new entry)
    oauth_state: str = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))

    with _iam_lock:
        # retrieve the user data from the IAM server's registry
        user_data: dict[str, Any] = _get_user_data(iam_server=iam_server,
                                                   user_id=oauth_state,
                                                   errors=errors,
                                                   logger=logger)
        if user_data:
            user_data[UserParam.LOGIN_ID] = user_id
            timeout: int = _get_login_timeout(iam_server=iam_server,
                                              errors=errors,
                                              logger=logger)
            if not errors:
                user_data[UserParam.LOGIN_EXPIRATION] = int(datetime.now(tz=TZ_LOCAL).timestamp()) + timeout \
                    if timeout else None
                redirect_uri: str = args.get(UserParam.REDIRECT_URI)
                user_data[UserParam.REDIRECT_URI] = redirect_uri

                # build the login url
                registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                             errors=errors,
                                                             logger=logger)
                if registry:
                    base_url: str = f"{registry[IamParam.URL_BASE]}/realms/{registry[IamParam.CLIENT_REALM]}"
                    result = (f"{base_url}/protocol/openid-connect/auth"
                              f"?response_type=code&scope=openid"
                              f"&client_id={registry[IamParam.CLIENT_ID]}"
                              f"&redirect_uri={redirect_uri}"
                              f"&state={oauth_state}")
    return result


def action_logout(iam_server: IamServer,
                  args: dict[str, Any],
                  errors: list[str] = None,
                  logger: Logger = None) -> None:
    """
    Logout the user, by removing all data associating it from *iam_server*'s registry.

    The user is identified by the attribute *user-id* or "login", provided in *args*.
    If successful, remove all data relating to the user from the *IAM* server's registry.
    Otherwise, this operation fails silently, unless an error has ocurred.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    """
    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    if user_id:
        with _iam_lock:
            # retrieve the data for all users in the IAM server's registry
            users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                              errors=errors,
                                                              logger=logger) or {}
            if user_id in users:
                users.pop(user_id)
                if logger:
                    logger.debug(msg=f"User '{user_id}' removed from {iam_server}'s registry")


def action_token(iam_server: IamServer,
                 args: dict[str, Any],
                 errors: list[str] = None,
                 logger: Logger = None) -> str:
    """
    Retrieve the authentication token for the user, from *iam_server*.

    The user is identified by the attribute *user-id* or *login*, provided in *args*.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token for user indicated, or *None* if error
    """
    # initialize the return variable
    result: str | None = None

    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    err_msg: str | None = None
    if user_id:
        with _iam_lock:
            # retrieve the user data in the IAM server's registry
            user_data: dict[str, Any] = _get_user_data(iam_server=iam_server,
                                                       user_id=user_id,
                                                       errors=errors,
                                                       logger=logger)
            token: str = user_data[UserParam.ACCESS_TOKEN] if user_data else None
            if token:
                access_expiration: int = user_data.get(UserParam.ACCESS_EXPIRATION)
                now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                if now < access_expiration:
                    result = token
                else:
                    # access token has expired
                    refresh_token: str = user_data[UserParam.REFRESH_TOKEN]
                    if refresh_token:
                        refresh_expiration = user_data[UserParam.REFRESH_EXPIRATION]
                        if now < refresh_expiration:
                            body_data: dict[str, str] = {
                                "grant_type": "refresh_token",
                                "refresh_token": refresh_token
                            }
                            now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                            token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                                          body_data=body_data,
                                                                          errors=errors,
                                                                          logger=logger)
                            # validate and store the token data
                            if token_data:
                                token_info: tuple[str, str] = __validate_and_store(iam_server=iam_server,
                                                                                   user_data=user_data,
                                                                                   token_data=token_data,
                                                                                   now=now,
                                                                                   errors=errors,
                                                                                   logger=logger)
                                result = token_info[1]
                            else:
                                # refresh token is no longer valid
                                user_data[UserParam.REFRESH_TOKEN] = None
                        else:
                            # refresh token has expired
                            err_msg = "Access and refresh tokens expired"
                            if logger:
                                logger.error(msg=err_msg)
                    else:
                        err_msg = "Access token expired, no refresh token available"
                        if logger:
                            logger.error(msg=err_msg)
            else:
                err_msg = f"User '{user_id}' not authenticated"
                if logger:
                    logger.error(msg=err_msg)
    else:
        err_msg = "User identification not provided"
        if logger:
            logger.error(msg=err_msg)

    if err_msg and isinstance(errors, list):
        errors.append(err_msg)

    return result


def action_callback(iam_server: IamServer,
                    args: dict[str, Any],
                    errors: list[str] = None,
                    logger: Logger = None) -> tuple[str, str] | None:
    """
    Entry point for the callback from *iam_server* via the front-end application, on authentication operations.

    The relevant expected arguments in *args* are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by *iam_server*, to be exchanged for the token

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental errors
    :param logger: optional logger
    :return: a tuple containing the reference user identification and the token obtained, or *None* if error
    """
    # initialize the return variable
    result: tuple[str, str] | None = None

    with _iam_lock:
        # retrieve the IAM server's data for all users
        users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                          errors=errors,
                                                          logger=logger) or {}
        # retrieve the OAuth2 state
        oauth_state: str = args.get("state")
        user_data: dict[str, Any] | None = None
        if oauth_state:
            for user, data in users.items():
                if user == oauth_state:
                    user_data = data
                    break

        # exchange 'code' received for the token
        if user_data:
            expiration: int = user_data["login-expiration"] or sys.maxsize
            if int(datetime.now(tz=TZ_LOCAL).timestamp()) > expiration:
                errors.append("Operation timeout")
            else:
                users.pop(oauth_state)
                code: str = args.get("code")
                body_data: dict[str, Any] = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": user_data.pop("redirect-uri")
                }
                now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                              body_data=body_data,
                                                              errors=errors,
                                                              logger=logger)
                # validate and store the token data
                if token_data:
                    result = __validate_and_store(iam_server=iam_server,
                                                  user_data=user_data,
                                                  token_data=token_data,
                                                  now=now,
                                                  errors=errors,
                                                  logger=logger)
        else:
            msg: str = f"State '{oauth_state}' not found in {iam_server}'s registry"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result


def action_exchange(iam_server: IamServer,
                    args: dict[str, Any],
                    errors: list[str] = None,
                    logger: Logger = None) -> dict[str, Any]:
    """
    Request *iam_server* to issue a token in exchange for the token obtained from another *IAM* server.

    The expected parameters in *args* are:
        - user-id: identification for the reference user (alias: 'login')
        - token: the token to be exchanged

    The typical data set returned contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental errors
    :param logger: optional logger
    :return: the data for the new token, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    # obtain the token to be exchanged
    token: str = args.get("access-token") if user_id else None

    claims: dict[str, Any] = token_get_claims(token=token,
                                              errors=errors,
                                              logger=logger) if token else None
    token_sub: str = claims["payload"].get("sub") if claims else None

    if token_sub:
        # HAZARD: only 'IAM_KEYCLOAK' is currently supported
        with _iam_lock:
            # retrieve the IAM server's registry
            registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                         errors=errors,
                                                         logger=logger)
            if registry:
                # make sure 'client_id' is linked to 'token_sub' at the IAM server
                body_data: dict[str, str] = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "audience": registry[IamParam.CLIENT_ID],
                    "subject_issuer": "oidc"
                }
                now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                              body_data=body_data,
                                                              errors=errors,
                                                              logger=logger)
                # validate and store the token data
                if token_data:
                    user_data: dict[str, Any] = {}
                    result = __validate_and_store(iam_server=iam_server,
                                                  user_data=user_data,
                                                  token_data=token_data,
                                                  now=now,
                                                  errors=errors,
                                                  logger=logger)
    else:
        msg: str = "User identification or token not provided"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def __assert_link(registry: dict[str, Any],
                  from_id: str,
                  errors: list[str] | None,
                  logger: Logger | None) -> None:

    # obtain the IAM server's internal user identification for 'from_id'
    url: str = f"{registry[IamParam.URL_BASE]}/admin/realms/{registry[IamParam.CLIENT_REALM]}/users"
    data: dict[str, str] = {
        "username": from_id,
        "exact": "true"
    }
    if logger:
        logger.debug(f"GET {url}, {json.dumps(obj=data,
                                              ensure_ascii=False)}")
    response: requests.Response = requests.get(url=url,
                                               data=data)


def __post_for_token(iam_server: IamServer,
                     body_data: dict[str, Any],
                     errors: list[str] | None,
                     logger: Logger | None) -> dict[str, Any] | None:
    """
    Send a POST request to obtain the authentication token data, and return the data received.

    For token acquisition, *body_data* will have the attributes:
        - "grant_type": "authorization_code"
        - "code": <16-character-random-code>
        - "redirect_uri": <redirect-uri>

    For token refresh, *body_data* will have the attributes:
        - "grant_type": "refresh_token"
        - "refresh_token": <current-refresh-token>

    For token exchange, *body_data* will have the attributes:
        - "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        - "subject_token": <token-to-be-exchanged>,
        - "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        - "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        - "audience": <client-id>,
        - "subject_issuer": "oidc"

    These attributes are then added to *body_data*:
        - "client_id": <client-id>,
        - "client_secret": <client-secret>,

    If the operation is successful, the token data is stored in the *IAM* server's registry, and returned.
    Otherwise, *errors* will contain the appropriate error message.

    The typical data set returned contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param body_data: the data to send in the body of the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the token data, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    err_msg: str | None = None
    with _iam_lock:
        # retrieve the IAM server's registry
        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                     errors=errors,
                                                     logger=logger)
        if registry:
            # complete the data to send in body of request
            body_data["client_id"] = registry[IamParam.CLIENT_ID]
            client_secret: str = registry[IamParam.CLIENT_SECRET]

            # obtain the token
            base_url: str = f"{registry[IamParam.URL_BASE]}/realms/{registry[IamParam.CLIENT_REALM]}"
            url: str = f"{base_url}/protocol/openid-connect/token"

            # log the POST ('client_secret' data must not be shown in log)
            if logger:
                logger.debug(msg=f"POST {url}, {json.dumps(obj=body_data,
                                                           ensure_ascii=False)}")
            if client_secret:
                body_data["client_secret"] = client_secret
            try:
                # typical return on a token request:
                # {
                #   "token_type": "Bearer",
                #   "access_token": <str>,
                #   "expires_in": <number-of-seconds>,
                #   "refresh_token": <str>,
                #   "refesh_expires_in": <number-of-seconds>
                # }
                response: requests.Response = requests.post(url=url,
                                                            data=body_data)
                if response.status_code == 200:
                    # request succeeded
                    result = response.json()
                    if logger:
                        logger.debug(msg=f"POST success, {json.dumps(obj=result,
                                                                     ensure_ascii=False)}")
                else:
                    # request resulted in error
                    err_msg = f"POST failure, status {response.status_code}, reason {response.reason}"
                    if hasattr(response, "content") and response.content:
                        err_msg += f", content '{response.content}'"
                    if logger:
                        logger.error(msg=err_msg)
            except Exception as e:
                # the operation raised an exception
                err_msg = exc_format(exc=e,
                                     exc_info=sys.exc_info())
                if logger:
                    logger.error(msg=err_msg)

    if err_msg and isinstance(errors, list):
        errors.append(err_msg)

    return result


def __validate_and_store(iam_server: IamServer,
                         user_data: dict[str, Any],
                         token_data: dict[str, Any],
                         now: int,
                         errors: list[str] | None,
                         logger: Logger) -> tuple[str, str] | None:
    """
    Validate and store the token data.

    The typical *token_data* contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param user_data: the aurthentication data kepth in *iam_server*'s registry
    :param token_data: the token data
    :param errors: incidental errors
    :param logger: optional logger
    :return: tuple containing the user identification and the validated and stored token, or *None* if error
    """
    # initialize the return variable
    result: tuple[str, str] | None = None

    with _iam_lock:
        # retrieve the IAM server's registry
        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                     errors=errors,
                                                     logger=logger)
        if registry:
            token: str = token_data.get("access_token")
            user_data["access-token"] = token
            # keep current refresh token if a new one is not provided
            if token_data.get("refresh_token"):
                user_data["refresh-token"] = token_data.get("refresh_token")
            user_data["access-expiration"] = now + token_data.get("expires_in")
            refresh_exp: int = user_data.get("refresh_expires_in")
            user_data["refresh-expiration"] = (now + refresh_exp) if refresh_exp else sys.maxsize
            # public_key: str = _get_public_key(iam_server=iam_server,
            #                                   errors=errors,
            #                                   logger=logger)
            recipient_attr = registry[IamParam.RECIPIENT_ATTR]
            login_id = user_data.pop("login-id", None)
            base_url: str = f"{registry[IamParam.URL_BASE]}/realms/{registry[IamParam.CLIENT_REALM]}"
            claims: dict[str, dict[str, Any]] = token_validate(token=token,
                                                               issuer=base_url,
                                                               recipient_id=login_id,
                                                               recipient_attr=recipient_attr,
                                                               # public_key=public_key,
                                                               errors=errors,
                                                               logger=logger)
            if claims:
                users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                                  errors=errors,
                                                                  logger=logger)
                # must test with 'not errors'
                if not errors:
                    user_id: str = login_id if login_id else claims["payload"][recipient_attr]
                    users[user_id] = user_data
                    result = (user_id, token)
    return result
