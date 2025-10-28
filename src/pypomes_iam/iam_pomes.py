from flask import Response, redirect, request, jsonify
from logging import Logger
from typing import Any

from .common_pomes import (
    _service_login, _service_logout,
    _service_callback, _service_token, _log_init
)
from .jusbr_pomes import _jusbr_logger, _jusbr_registry
from .keycloak_pomes import _keycloak_logger, _keycloak_registry


# @flask_app.route(rule=<login_endpoint>,  # JUSBR_LOGIN_ENDPOINT: /iam/jusbr:login
#                  methods=["GET"])
# @flask_app.route(rule=<login_endpoint>,  # KEYCLOAK_LOGIN_ENDPOINT: /iam/keycloak:logout
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the JusBR login service.

    Redirect the request to the JusBR authentication page, with the appropriate parameters.

    :return: the response from the redirect operation
    """
    logger: Logger
    registry: dict[str, Any]
    if request.endpoint == "jusbr-login":
        logger = _jusbr_logger
        registry = _jusbr_registry
    else:
        logger = _keycloak_logger
        registry = _keycloak_registry

    # log the request
    if logger:
        logger.debug(msg=_log_init(request=request))

    # obtain the redirect URL
    auth_url: str = _service_login(registry=registry,
                                   args=request.args,
                                   logger=logger)
    # redirect the request
    result: Response = redirect(location=auth_url)

    # log the response
    if logger:
        logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<logout_endpoint>,  # JUSBR_LOGOUT_ENDPOINT: /iam/jusbr:logout
#                  methods=["GET"])
# @flask_app.route(rule=<login_endpoint>,  # KEYCLOAK_LOGOUT_ENDPOINT: /iam/keycloak:logout
#                  methods=["GET"])
def service_logout() -> Response:
    """
    Entry point for the JusBR logout service.

    Remove all data associating the user with JusBR from the registry.

    :return: response *OK*
    """
    logger: Logger
    registry: dict[str, Any]
    if request.endpoint == "jusbr-logout":
        logger = _jusbr_logger
        registry = _jusbr_registry
    else:
        logger = _keycloak_logger
        registry = _keycloak_registry

    # log the request
    if logger:
        logger.debug(msg=_log_init(request=request))

    # logout the user
    _service_logout(registry=registry,
                    args=request.args,
                    logger=logger)

    result: Response = Response(status=200)

    # log the response
    if logger:
        logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<callback_endpoint>,  # JUSBR_CALLBACK_ENDPOINT: /iam/jusbr:callback
#                  methods=["GET", "POST"])
# @flask_app.route(rule=<callback_endpoint>,  # KEYCLOAK_CALLBACK_ENDPOINT: /iam/keycloak:callback
#                  methods=["POST"])
def service_callback() -> Response:
    """
    Entry point for the callback from JusBR on authentication operation.

    :return: the response containing the token, or *BAD REQUEST*
    """
    logger: Logger
    registry: dict[str, Any]
    if request.endpoint == "jusbr-callback":
        logger = _jusbr_logger
        registry = _jusbr_registry
    else:
        logger = _keycloak_logger
        registry = _keycloak_registry

    # log the request
    if logger:
        logger.debug(msg=_log_init(request=request))

    # process the callback operation
    errors: list[str] = []
    token_data: tuple[str, str] = _service_callback(registry=registry,
                                                    args=request.args,
                                                    errors=errors,
                                                    logger=logger)
    result: Response
    if errors:
        result = jsonify({"errors": "; ".join(errors)})
        result.status_code = 400
    else:
        result = jsonify({
            "user_id": token_data[0],
            "access_token": token_data[1]})

    # log the response
    if logger:
        logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<token_endpoint>,  # JUSBR_TOKEN_ENDPOINT: /iam/jusbr:get-token
#                  methods=["GET"])
# @flask_app.route(rule=<token_endpoint>,  # JUSBR_TOKEN_ENDPOINT: /iam/jusbr:get-token
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for retrieving the JusBR token.

    :return: the response containing the token, or *UNAUTHORIZED*
    """
    logger: Logger
    registry: dict[str, Any]
    if request.endpoint == "jusbr-token":
        logger = _jusbr_logger
        registry = _jusbr_registry
    else:
        logger = _keycloak_logger
        registry = _keycloak_registry

    # log the request
    if logger:
        logger.debug(msg=_log_init(request=request))

    # retrieve the token
    errors: list[str] = []
    token: str = _service_token(registry=registry,
                                args=request.args,
                                errors=errors,
                                logger=logger)
    result: Response
    if token:
        result = jsonify({"token": token})
    else:
        result = Response("; ".join(errors))
        result.status_code = 401

    # log the response
    if logger:
        logger.debug(msg=f"Response {result}")

    return result
