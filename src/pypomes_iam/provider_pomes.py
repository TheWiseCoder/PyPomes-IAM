import json
import requests
import sys
from base64 import b64encode
from datetime import datetime
from enum import StrEnum
from flask import Flask, Response, request, jsonify
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL,
    env_get_str, env_get_strs, exc_format, func_get_defaulted_params
)
from threading import Lock
from typing import Any, Final


class ProviderParam(StrEnum):
    """
    Parameters for configuring a *JWT* token provider.
    """
    AUTH_URL = "auth-url"
    BODY_DATA = "body-data"
    CUSTOM_AUTH = "custom-auth"
    HEADER_DATA = "headers-data"
    USER_ID = "user-id"
    USER_SECRET = "user-secret"
    ACCESS_TOKEN = "access-token"
    ACCESS_EXPIRATION = "access-expiration"
    REFRESH_TOKEN = "refresh-token"
    REFRESH_EXPIRATION = "refresh-expiration"


# the logger for IAM service operations
# (used exclusively at the HTTP endpoints - all other functions receive the logger as parameter)
__JWT_LOGGER: Logger | None = None


def __get_provider_data() -> dict[str, dict[ProviderParam, Any]]:
    """
    Obtain the configuration data for select *JWT* providers.

    The configuration parameters for the JWT providers are specified with environment variables,
    or dynamically with *provider_setup_server()*. Specifying configuration parameters with
    environment variables can be done by following these steps:

    1. Specify *<APP_PREFIX>_JWT_PROVIDERS* with a list of names (typically, in lower-case), and the data set
       below for each providers, where *<JWT>* stands for the provider's name in upper-case:
          - *<APP_PREFIX>_<JWT>_AUTH_URL*             (required)
          - *<APP_PREFIX>_<JWT>_BODY_DATA*            (optional)
          - *<APP_PREFIX>_<JWT>_CUSTOM_AUTH*          (optional)
          - *<APP_PREFIX>_<JWT>_HEADER_DATA*          (optional)
          - *<APP_PREFIX>_<JWT>_USER_ID*              (required)
          - *<APP_PREFIX>_<JWT>_USER_SECRET*          (required)

    2. The special enVironment variable *<APP_PREFIX>_JWT_ENDPOINT_TOKEN* identifies the endpoint from which
       to obtain JWT tokens. It is not part of the *JWT* providers' setup, but is meant to be used
       by function *provider_setup_endpoint()*, wherein the value in that variable would represent the
       default value for its parameter.

    :return: the configuration data for the select *JWT* providers.
    """
    # initialize the return variable
    result: dict[str, dict[ProviderParam, Any]] = {}

    servers: list[str] = env_get_strs(key=f"{APP_PREFIX}_JWT_SERVERS") or []
    for server in servers:
        prefix = server.upper()
        result[server] = {
            ProviderParam.AUTH_URL: env_get_str(key=f"{APP_PREFIX}_{prefix}_AUTH_URL"),
            ProviderParam.BODY_DATA: env_get_str(key=f"{APP_PREFIX}_{prefix}_BODY_DATA"),
            ProviderParam.CUSTOM_AUTH: env_get_str(key=f"{APP_PREFIX}_{prefix}_CUSTOM_AUTH"),
            ProviderParam.HEADER_DATA: env_get_str(key=f"{APP_PREFIX}_{prefix}_HEADER_DATA"),
            ProviderParam.USER_ID: env_get_str(key=f"{APP_PREFIX}_{prefix}_USER_ID"),
            ProviderParam.USER_SECRET: env_get_str(key=f"{APP_PREFIX}_{prefix}_USER_SECRET"),
            ProviderParam.ACCESS_TOKEN: None,
            ProviderParam.ACCESS_EXPIRATION: 0,
            ProviderParam.REFRESH_TOKEN: None,
            ProviderParam.REFRESH_EXPIRATION: 0
        }

    return result


# structure:
# {
#    <provider-id>: {
#      "url": <strl>,
#      "user": <str>,
#      "pwd": <str>,
#      "custom-auth": <bool>,
#      "headers-data": <dict[str, str]>,
#      "body-data": <dict[str, str],
#      "access-token": <str>,
#      "access-expiration": <timestamp>,
#      "refresh-token": <str>,
#      "refresh-expiration": <timestamp>
#    }
# }
_provider_registry: Final[dict[str, dict[str, Any]]] = __get_provider_data()

# the lock protecting the data in '_provider_registry'
# (because it is 'Final' and set at declaration time, it can be accessed through simple imports)
_provider_lock: Final[Lock] = Lock()


def provider_setup_server(provider_id: str,
                          auth_url: str = None,
                          user_id: str = None,
                          user_secret: str = None,
                          custom_auth: tuple[str, str] = None,
                          header_data: dict[str, str] = None,
                          body_data: dict[str, str] = None) -> None:
    """
    Setup the *JWT* provider *provider_id*.

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variable.

    If specified, *custom_auth* provides key names for sending credentials (username and password, in this order)
    as key-value pairs in the body of the request. Otherwise, the external provider *provider_id* uses the standard
    HTTP Basic Authorization scheme, wherein the credentials are B64-encoded and sent in the request headers.

    Optional constant key-value pairs (such as ['Content-Type', 'application/x-www-form-urlencoded']), to be
    added to the request headers, may be specified in *headers_data*. Likewise, optional constant key-value pairs
    (such as ['grant_type', 'client_credentials']), to be added to the request body, may be specified in *body_data*.

    :param provider_id: the provider's identification
    :param auth_url: the url to request *JWT* tokens with
    :param user_id: the basic authorization user
    :param user_secret: the basic authorization password
    :param custom_auth: optional key names for sending the credentials as key-value pairs in the body of the request
    :param header_data: optional key-value pairs to be added to the request headers
    :param body_data: optional key-value pairs to be added to the request body
    """
    global _provider_registry

    # obtain the defaulted parameters
    defaulted_params: list[str] = func_get_defaulted_params()

    # read from the environment variables
    prefix: str = provider_id.upper()
    if "auth_url" in defaulted_params:
        auth_url = env_get_str(key=f"{APP_PREFIX}_{prefix}_AUTH_URL")
    if "user_id" in defaulted_params:
        user_id = env_get_str(key=f"{APP_PREFIX}_{prefix}_USER_ID")
    if "user_secret" in defaulted_params:
        user_secret = env_get_str(key=f"{APP_PREFIX}_{prefix}_USER_SECRET")
    if "custom_auth" in defaulted_params:
        custom_auth = env_get_str(key=f"{APP_PREFIX}_{prefix}_CUSTOM_AUTH")
    if "header_data" in defaulted_params:
        header_data = env_get_str(key=f"{APP_PREFIX}_{prefix}_HEADER_DATA")
    if "body_data" in defaulted_params:
        body_data = env_get_str(key=f"{APP_PREFIX}_{prefix}_BODY_DATA")

    with _provider_lock:
        _provider_registry[provider_id] = {
            ProviderParam.AUTH_URL: auth_url,
            ProviderParam.USER_ID: user_id,
            ProviderParam.USER_SECRET: user_secret,
            ProviderParam.CUSTOM_AUTH: custom_auth,
            ProviderParam.HEADER_DATA: header_data,
            ProviderParam.BODY_DATA: body_data,
            # dynamically set
            ProviderParam.ACCESS_TOKEN: None,
            ProviderParam.ACCESS_EXPIRATION: 0,
            ProviderParam.REFRESH_TOKEN: None,
            ProviderParam.REFRESH_EXPIRATION: 0
        }


def provider_setup_endpoint(flask_app: Flask,
                            token_endpoint: str = None) -> None:
    """
    Setup the endpoint for requesting token from the registered *JWT* providers.

    if *get_token_endpoint* is not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variable.

    :param flask_app: the Flask application
    :param token_endpoint: endpoint for the callback from the front end
    """
    # obtain the defaulted parameters
    defaulted_params: list[str] = func_get_defaulted_params()

    # read from the environment variable
    if "token_endpoint" in defaulted_params:
        token_endpoint = env_get_str(key=f"{APP_PREFIX}_JWT_ENDPOINT_TOKEN")

    # establish the endpoints
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint=f"jwt-callback",
                               view_func=service_jwt_token,
                               methods=["GET"])


def provider_setup_logger(logger: Logger) -> None:
    """
    Register the logger for HTTP services.

    :param logger: the logger to be registered
    """
    global __JWT_LOGGER
    __JWT_LOGGER = logger


# @flask_app.route(rule=<token_endpoint>,  # IAM_ENDPOINT_TOKEN
#                  methods=["GET"])
def service_jwt_token() -> Response:
    """
    Entry point for retrieving a token from the *JWT* provider.

    The provider is identified by the request parameter *jwt-provider*.

    On success, the returned *Response* will contain the following JSON:
        {
            "access-token": <token>
        }

    :return: *Response* containing the JWT token, or *BAD REQUEST*
    """
    # log the request
    if __JWT_LOGGER:
        params: str = json.dumps(obj=request.args,
                                 ensure_ascii=False)
        __JWT_LOGGER.debug(msg=f"Request {request.method}:{request.path}, params {params}")

    # obtain the provider JWT
    provider_id: str = request.args.get("jwt-provider")

    # retrieve the token
    token: str | None = None
    errors: list[str] = []
    if provider_id:
        token: str = action_jwt_token(provider_id=provider_id,
                                      errors=errors,
                                      logger=__JWT_LOGGER)
    else:
        msg: str = "JWT provider not informed"
        errors.append(msg)
        if __JWT_LOGGER:
            __JWT_LOGGER.error(msg=msg)

    result: Response
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = jsonify({"access-token": token})
    if __JWT_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __JWT_LOGGER.debug(msg=f"Response {result}")

    return result


def action_jwt_token(provider_id: str,
                     errors: list[str] = None,
                     logger: Logger = None) -> str | None:
    """
    Obtain an JWT token from the external provider *provider_id*.

    :param provider_id: the provider's identification
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the JWT token, or *None* if error
    """
    global _provider_registry

    # initialize the return variable
    result: str | None = None

    with _provider_lock:
        provider: dict[str, Any] = _provider_registry.get(provider_id)
        if provider:
            now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
            if now < provider.get(ProviderParam.ACCESS_EXPIRATION):
                # retrieve the stored access token
                result = provider.get(ProviderParam.ACCESS_TOKEN)
            else:
                # access token has expired
                header_data: dict[str, str] | None = None
                body_data: dict[str, str] | None = None
                url: str = provider.get(ProviderParam.AUTH_URL)
                refresh_token: str = provider.get(ProviderParam.REFRESH_TOKEN)
                if refresh_token:
                    # refresh token exists
                    refresh_expiration: int = provider.get(ProviderParam.REFRESH_EXPIRATION)
                    if now < refresh_expiration:
                        # refresh token has not expired
                        header_data: dict[str, str] = {
                            "Content-Type": "application/json"
                        }
                        body_data: dict[str, str] = {
                            "grant_type": "refresh_token",
                            "refresh_token": refresh_token
                        }
                if not body_data:
                    # refresh token does not exist or has expired
                    user: str = provider.get(ProviderParam.USER_ID)
                    pwd: str = provider.get(ProviderParam.USER_SECRET)
                    headers_data: dict[str, str] = provider.get(ProviderParam.HEADER_DATA) or {}
                    body_data: dict[str, str] = provider.get(ProviderParam.BODY_DATA) or {}
                    custom_auth: tuple[str, str] = provider.get(ProviderParam.CUSTOM_AUTH)
                    if custom_auth:
                        body_data[custom_auth[0]] = user
                        body_data[custom_auth[1]] = pwd
                    else:
                        enc_bytes: bytes = b64encode(f"{user}:{pwd}".encode())
                        headers_data["Authorization"] = f"Basic {enc_bytes.decode()}"

                # obtain the token
                token_data: dict[str, Any] = __post_for_token(url=url,
                                                              header_data=header_data,
                                                              body_data=body_data,
                                                              errors=errors,
                                                              logger=logger)
                if token_data:
                    result = token_data.get("access_token")
                    provider[ProviderParam.ACCESS_TOKEN] = result
                    provider[ProviderParam.ACCESS_EXPIRATION] = now + token_data.get("expires_in")
                    refresh_token = token_data.get("refresh_token")
                    if refresh_token:
                        provider[ProviderParam.REFRESH_TOKEN] = refresh_token
                        refresh_exp: int = token_data.get("refresh_expires_in")
                        provider[ProviderParam.REFRESH_EXPIRATION] = (now + refresh_exp) \
                            if refresh_exp else sys.maxsize

        elif logger or isinstance(errors, list):
            msg: str = f"Unknown provider '{provider_id}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result


def __post_for_token(url: str,
                     header_data: dict[str, str],
                     body_data: dict[str, Any],
                     errors: list[str] | None,
                     logger: Logger | None) -> dict[str, Any] | None:
    """
    Send a *POST* request to *url* and return the token data obtained.

    Token acquisition and token refresh are the two types of requests contemplated herein.
    For the former, *header_data* and *body_data* will have contents customized to the specific provider,
    whereas the latter's *body_data* will contain these two attributes:
        - "grant_type": "refresh_token"
        - "refresh_token": <current-refresh-token>

    The typical data set returned contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param url: the target URL
    :param header_data: the data to send in the header of the request
    :param body_data: the data to send in the body of the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the token data, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    # log the POST
    if logger:
        logger.debug(msg=f"POST {url}, {json.dumps(obj=body_data,
                                                   ensure_ascii=False)}")
    try:
        response: requests.Response = requests.post(url=url,
                                                    data=body_data,
                                                    headers=header_data,
                                                    timeout=None)
        if response.status_code == 200:
            # request succeeded
            result = response.json()
            if logger:
                logger.debug(msg=f"POST success, status {response.status_code}")
        else:
            # request failed, report the problem
            msg: str = (f"POST failure, "
                        f"status {response.status_code}, reason {response.reason}")
            if hasattr(response, "content") and response.content:
                msg += f", content '{response.content}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)
    except Exception as e:
        # the operation raised an exception
        err_msg = exc_format(exc=e,
                             exc_info=sys.exc_info())
        msg: str = f"POST error, {err_msg}"
        if logger:
            logger.debug(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result
