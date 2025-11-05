import json
from flask import Request, Response, request, jsonify
from logging import Logger
from typing import Any

from .iam_common import (
    IamServer, IamParam, _iam_lock,
    _get_iam_registry, _get_public_key,
    _iam_server_from_endpoint, _iam_server_from_issuer
)
from .iam_actions import (
    action_login, action_logout,
    action_token, action_exchange, action_callback
)
from .token_pomes import token_get_claims, token_validate

# the logger for IAM service operations
# (used exclusively at the HTTP endpoints - all other functions receive the logger as parameter)
__IAM_LOGGER: Logger | None = None


def jwt_required(func: callable) -> callable:
    """
    Create a decorator to authenticate service endpoints with JWT tokens.

    :param func: the function being decorated
    """
    # ruff: noqa: ANN003 - Missing type annotation for *{name}
    def wrapper(*args, **kwargs) -> Response:
        response: Response = __request_validate(request=request)
        return response if response else func(*args, **kwargs)

    # prevent a rogue error ("View function mapping is overwriting an existing endpoint function")
    wrapper.__name__ = func.__name__

    return wrapper


def __request_validate(request: Request) -> Response:
    """
    Verify whether the HTTP *request* has the proper authorization, as per the JWT standard.

    This implementation assumes that HTTP requests are handled with the *Flask* framework.
    Because this code has a high usage frequency, only authentication failures are logged.

    :param request: the *request* to be verified
    :return: *None* if the *request* is valid, otherwise a *Response* reporting the error
    """
    # initialize the return variable
    result: Response | None = None

    # retrieve the authorization from the request header
    auth_header: str = request.headers.get("Authorization")

    # validate the authorization token
    bad_token: bool = True
    if auth_header and auth_header.startswith("Bearer "):
        # extract and validate the JWT access token
        token: str = auth_header.split(" ")[1]
        claims: dict[str, Any] = token_get_claims(token=token)
        if claims:
            issuer: str = claims["payload"].get("iss")
            public_key: str | None = None
            recipient_attr: str | None = None
            recipient_id: str = request.values.get("user-id") or request.values.get("login")
            with _iam_lock:
                iam_server: IamServer = _iam_server_from_issuer(issuer=issuer,
                                                                errors=None,
                                                                logger=__IAM_LOGGER)
                if iam_server:
                    # validate the token's recipient only if a user identification is provided
                    if recipient_id:
                        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                                     errors=None,
                                                                     logger=__IAM_LOGGER)
                        if registry:
                            recipient_attr = registry[IamParam.RECIPIENT_ATTR]
                    public_key = _get_public_key(iam_server=iam_server,
                                                 errors=None,
                                                 logger=__IAM_LOGGER)
            # validate the token (log errors, only)
            errors: list[str] = []
            if token_validate(token=token,
                              issuer=issuer,
                              recipient_id=recipient_id,
                              recipient_attr=recipient_attr,
                              public_key=public_key,
                              errors=errors):
                # token is valid
                bad_token = False
            elif __IAM_LOGGER:
                __IAM_LOGGER.error("; ".join(errors))
        if bad_token and __IAM_LOGGER:
            __IAM_LOGGER.error(f"Authorization refused for token {token}")

    # deny the authorization
    if bad_token:
        result = Response(response="Authorization failed",
                          status=401)
    return result


def iam_setup_logger(logger: Logger) -> None:
    """
    Register the logger for HTTP services.

    :param logger: the logger to be registered
    """
    global __IAM_LOGGER
    __IAM_LOGGER = logger


# @flask_app.route(rule=<login_endpoint>,  # IAM_ENDPOINT_LOGIN
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the IAM server's login service.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    These are the expected request parameters:
        - user-id: optional, identifies the reference user (alias: 'login')
        - redirect-uri: a parameter to be added to the query part of the returned URL
        -target-idp: optionally, identify a target identity provider for the login operation

    If provided, the user identification will be validated against the authorization data
    returned by *iam_server* upon login. On success, the following JSON, containing the appropriate
    URL for invoking the IAM server's authentication page, is returned:
        {
            "login-url": <login-url>
        }

    :return: *Response* with the URL for invoking the IAM server's authentication page, or *BAD REQUEST* if error
    """
    # declare the return variable
    result: Response | None = None

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # obtain the login URL
            login_url: str = action_login(iam_server=iam_server,
                                          args=request.args,
                                          errors=errors,
                                          logger=__IAM_LOGGER)
            if login_url:
                result = jsonify({"login-url": login_url})
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)

    # log the response
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Response {result}; {result.get_data(as_text=True)}")

    return result


# @flask_app.route(rule=<logout_endpoint>,  # IAM_ENDPOINT_LOGOUT
#                  methods=["GET"])
def service_logout() -> Response:
    """
    Entry point for the IAM server's logout service.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    The user is identified by the attribute *user-id* or "login", provided as a request parameter.
    If successful, remove all data relating to the user from the *IAM* server's registry.
    Otherwise, this operation fails silently, unless an error has ocurred.

    :return: *Response NO CONTENT*, or *BAD REQUEST* if error
    """
    # declare the return variable
    result: Response | None

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # logout the user
            action_logout(iam_server=iam_server,
                          args=request.args,
                          errors=errors,
                          logger=__IAM_LOGGER)
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = Response(status=204)

    if __IAM_LOGGER:
        # log the response
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<callback_endpoint>,  # IAM_ENDPOINT_CALLBACK
#                  methods=["GET", "POST"])
def service_callback() -> Response:
    """
    Entry point for the callback from the IAM server on authentication operation.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    This callback is invoked from a front-end application after a successful login at the
    *IAM* server's login page, forwarding the data received. In a typical OAuth2 flow faction,
    this data is then used to effectively obtain the token from the *IAM* server.

    The relevant expected request arguments are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by the IAM server, to be exchanged for the token

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    errors: list[str] = []
    token_data: tuple[str, str] | None = None
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # process the callback operation
            token_data = action_callback(iam_server=iam_server,
                                         args=request.args,
                                         errors=errors,
                                         logger=__IAM_LOGGER)
    result: Response
    if errors:
        result = jsonify({"errors": "; ".join(errors)})
        result.status_code = 400
    else:
        result = jsonify({"user-id": token_data[0],
                          "access-token": token_data[1]})
    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<callback_endpoint>,  # KEYCLOAK_ENDPOINT_EXCHANGE
#                  methods=["POST"])
def service_exchange() -> Response:
    """
    Entry point for requesting the *IAM* server to exchange the token.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    If the exchange is successful, the token data is stored in the *IAM* server's registry, and returned.
    Otherwise, *errors* will contain the appropriate error message.

    The expected request parameters are:
        - user-id: identification for the reference user (alias: 'login')
        - access-token: the token to be exchanged

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <the-exchanged-token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        # exchange the token
        token_info: tuple[str, str] | None = None
        if iam_server:
            errors: list[str] = []
            token_info = action_exchange(iam_server=iam_server,
                                         args=request.args,
                                         errors=errors,
                                         logger=__IAM_LOGGER)
    result: Response
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = jsonify({"user-id": token_info[0],
                          "access-token": token_info[1]})
    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}; {result.get_data(as_text=True)}")

    return result


# @flask_app.route(rule=/iam/jusbr:callback,
#                  methods=["GET"])
def service_callback_and_exchange() -> Response:
    """
    Entry point for the callback from the IAM server on authentication operation, with subsequent token exchange.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service, and suffixed with the string *_to_*
    followed by the name of the *IAM* server in charge of the token exchange. The prefixing, but not the suffixing,
    is done automatically if the endpoint is established with a call to *iam_setup_endpoints()*.

    This callback is invoked from a front-end application after a successful login at the
    *IAM* server's login page, forwarding the data received. In a typical OAuth2 flow faction,
    this data is then used to effectively obtain the token from the *IAM* server.
    This token is stored and thereafter, a corresponding token is requested from another IAM *server*,
    in a scheme known as "token exchange". This new token, along with the reference user identification,
    are then stored. Note that the original token is the one actually returned.

    The relevant expected request arguments are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by the IAM server, to be exchanged for the token

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <the-original-token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # declare the return variable
    result: Response | None = None

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        # obtain the login URL
        token_info: tuple[str,  str] = action_callback(iam_server=iam_server,
                                                       args=request.args,
                                                       errors=errors,
                                                       logger=__IAM_LOGGER)
        if token_info:
            args: dict[str, str] = {
                "user-id": token_info[0],
                "access-token": token_info[1]
            }
            # retrieve the exchange IAM server
            pos: int = request.endpoint.index("_to_")
            exchange_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint[pos+4],
                                                                   errors=errors,
                                                                   logger=__IAM_LOGGER)
            token_info = action_exchange(iam_server=exchange_server,
                                         args=args,
                                         logger=__IAM_LOGGER)
            if token_info:
                result = jsonify({"user-id": token_info[0],
                                  "access-token": token_info[1]})
    if errors:
        result = Response("; ".join(errors))
        result.status_code = 400

    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<token_endpoint>,  # IAM_ENDPOINT_TOKEN
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for retrieving a token from the *IAM* server.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    The user is identified by the attribute *user-id* or "login", provided as a request parameter.

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <token>
        }

    :return: *Response* containing the user reference identification and the token, or *BAD REQUEST*
    """
    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=_log_init(request=request))

    # obtain the user's identification
    args: dict[str, Any] = request.args
    user_id: str = args.get("user-id") or args.get("login")

    errors: list[str] = []
    token: str | None = None
    if user_id:
        with _iam_lock:
            # retrieve the IAM server
            iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                              errors=errors,
                                                              logger=__IAM_LOGGER)
            if iam_server:
                # retrieve the token
                errors: list[str] = []
                token: str = action_token(iam_server=iam_server,
                                          args=args,
                                          errors=errors,
                                          logger=__IAM_LOGGER)
    else:
        msg: str = "User identification not provided"
        errors.append(msg)
        if __IAM_LOGGER:
            __IAM_LOGGER.error(msg=msg)

    result: Response
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = jsonify({"user-id": user_id,
                          "access-token": token})
    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}")

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
