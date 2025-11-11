import json
from flask import Request, Response, request, jsonify
from pypomes_crypto import jwt_get_claim, jwt_validate
from logging import Logger
from typing import Any

from .iam_common import (
    IamServer, ServerParam, _iam_lock,
    _get_iam_registry, _get_iam_property, _get_public_key,
    _iam_server_from_endpoint, _iam_server_from_issuer
)
from .iam_actions import (
    iam_login, iam_logout, iam_callback,
    iam_exchange, iam_refresh, iam_token, iam_userinfo
)

# the logger for IAM service operations
# (used exclusively at the HTTP endpoints - all other functions receive the logger as parameter)
__IAM_LOGGER: Logger | None = None


def jwt_required(func: callable) -> callable:
    """
    Create a decorator to authenticate service endpoints with JWT tokens.

    The decorated function must be a registered endpoint to a *Flask* application.

    :param func: the function being decorated
    :return: the return from the call to *func*, or a *Response NOT AUTHORIZED* if the authentication failed
    """
    # ruff: noqa: ANN003 - Missing type annotation for *{name}
    def wrapper(*args, **kwargs) -> Response:
        response: Response = __request_validate(req=request)
        return response if response else func(*args, **kwargs)

    # prevent a rogue error ("View function mapping is overwriting an existing endpoint function")
    wrapper.__name__ = func.__name__

    return wrapper


def __request_validate(req: Request) -> Response:
    """
    Verify whether the HTTP *request* has the proper authorization, as per the JWT standard.

    This implementation assumes that HTTP requests are handled with the *Flask* framework.
    Because this code has a high usage frequency, only authentication failures are logged.

    :param req: the *request* to be verified
    :return: *None* if the *request* is valid, otherwise a *Response NOT AUTHORIZED*
    """
    # initialize the return variable
    result: Response | None = None

    # validate the authorization token
    bad_token: bool = True
    token: str = __get_bearer_token(req=req)
    if token:
        # extract token issuer
        issuer: str = jwt_get_claim(token=token,
                                    key="iss",
                                    logger=__IAM_LOGGER)
        public_key: str | None = None
        recipient_attr: str | None = None
        recipient_id: str = (req.values.get("user-id") or req.values.get("login") or
                             (req.get_json(silent=True) or {}).get("user-id") or
                             (req.get_json(silent=True) or {}).get("login"))
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
                        recipient_attr = registry[ServerParam.RECIPIENT_ATTR]
                public_key = _get_public_key(iam_server=iam_server,
                                             errors=None,
                                             logger=__IAM_LOGGER)
            # validate the token, with or without the public key
            if jwt_validate(token=token,
                            issuer=issuer,
                            recipient_id=recipient_id,
                            recipient_attr=recipient_attr,
                            public_key=public_key,
                            logger=__IAM_LOGGER):
                # token is valid
                bad_token = False

    # deny the authorization
    if bad_token:
        __IAM_LOGGER.error(f"Authorization refused for token {token}")
        result = Response(response="Not authorized",
                          status=401)
    return result


def __get_bearer_token(req: Request) -> str:
    """
    Retrieve the bearer token sent in the header of *request*.

    This implementation assumes that HTTP requests are handled with the *Flask* framework.

    :param req: the *request* to retrieve the token from
    :return: the bearer token, or *None* if not found
    """
    # initialize the return variable
    result: str | None = None

    # retrieve the authorization from the request header
    auth_header: str = req.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        result: str = auth_header.split(" ")[1]

    return result


def iam_setup_logger(logger: Logger) -> None:
    """
    Register the logger for HTTP services.

    :param logger: the logger to be registered
    """
    global __IAM_LOGGER
    __IAM_LOGGER = logger


# @flask_app.route(rule=<setup-server-endpoint>,
#                  methods=["POST"])
def service_setup_server() -> Response:
    """
    Entry point to setup a *IAM* server.

    These are the expected parameters in the request's body, in a JSON or as form data:
        - *iam_server*: identifies the supported *IAM* server
        - *admin_id*: identifies the realm administrator
        - *admin_secret*: password for the realm administrator
        - *client_id*: the client's identification with the *IAM* server
        - *client_realm*: the client's realm
        - *client_secret*: the client's password with the *IAM* server
        - *login_timeout*: timeout for login authentication (in seconds,defaults to no timeout)
        - *k_lifetime*: how long to use *IAM* server's public key, before refreshing it (in seconds)
        - *recipient_attr*: attribute in the token's payload holding the token's subject
        - *rl_base*: base URL to request services

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variables. Most parameters are required to have values, which must be assigned either
    throught the function invocation, or from the corresponding environment variables.

    The parameters *admin_id* and *admin_secret* are required only if performing administrative tasks is intended.
    The optional parameter *ogin_timeout* refers to the maximum time in seconds allowed for the user
    to login at the *IAM* server's login page, and defaults to no time limit.

    The parameter *client_secret* is required in most requests to the *IAM* server. In the case
    it is not provided, but *admin_id* and *admin_secret* are, it is obtained from the *IAM* server itself
    the first time it is needed.

    :return: *Response OK*
    """
    # retrieve the request arguments
    args: dict[str, Any] = dict(request.get_json(silent=True) or request.form or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    # setup the server
    from .iam_pomes import iam_setup_server
    iam_setup_server(**args)
    result = Response(status=200)

    # log the response
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<login-endpoint>,
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the *IAM* server's login service.

    The expected request parameters are:
        - user-id: optional, identifies the reference user (alias: 'login')
        - redirect-uri: a parameter to be added to the query part of the returned URL
        -target-idp: optionally, identify a target identity provider for the login operation

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

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

    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # obtain the login URL
            login_url: str = iam_login(iam_server=iam_server,
                                       args=args,
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


# @flask_app.route(rule=<logout-endpoint>,
#                  methods=["POST"])
@jwt_required
def service_logout() -> Response:
    """
    Entry point for the *IAM* server's logout service.

    The user is identified by the attribute *user-id* or "login", provided in the body's *JSON*.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    If successful, remove all data relating to the user from the *IAM* server's registry.
    Otherwise, this operation fails silently, unless an error has ocurred.

    :return: *Response NO CONTENT*, or *BAD REQUEST* if error
    """
    # declare the return variable
    result: Response | None

    # retrieve the request arguments
    args: dict[str, Any] = dict(request.get_json(silent=True) or request.form or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # logout the user
            iam_logout(iam_server=iam_server,
                       args=args,
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


# @flask_app.route(rule=<callback-endpoint>,
#                  methods=["GET"])
def service_callback() -> Response:
    """
    Entry point for the callback from the *IAM* server on authentication operation.

    The expected request arguments are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by the IAM server, to be exchanged for the token

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    This callback is invoked from a front-end application after a successful login at the
    *IAM* server's login page, forwarding the data received. In a typical OAuth2 flow faction,
    this data is then used to effectively obtain the token from the *IAM* server.

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    token_data: tuple[str, str] | None = None
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # process the callback operation
            token_data = iam_callback(iam_server=iam_server,
                                      args=args,
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


# @flask_app.route(rule=<exchange-endpoint>,
#                  methods=["POST"])
def service_exchange() -> Response:
    """
    Entry point for requesting the *IAM* server to exchange the token.

    The expected request parameters, to be found in the body *JSON*, are:
        - user-id: identification for the reference user (alias: 'login')
        - access-token: the token to be exchanged

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    If the exchange is successful, the token data is stored in the *IAM* server's registry, and returned.
    Otherwise, *errors* will contain the appropriate error message.

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <the-exchanged-token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # retrieve the request arguments
    args: dict[str, Any] = dict(request.get_json(silent=True) or request.form or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
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
            token_info = iam_exchange(iam_server=iam_server,
                                      args=args,
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


# @flask_app.route(rule=<callback-exchange-endpoint>,
#                  methods=["GET"])
def service_callback_exchange() -> Response:
    """
    Entry point for the callback from the IAM server on authentication operation, with subsequent token exchange.

    The expected request arguments are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by the IAM server, to be exchanged for the token

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

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <the-original-token>
        }

    :return: *Response* containing the reference user identification and the token, or *BAD REQUEST*
    """
    # declare the return variable
    result: Response | None = None

    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args or {})

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        # obtain the login URL
        token_info: tuple[str,  str] = iam_callback(iam_server=iam_server,
                                                    args=args,
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
            token_info = iam_exchange(iam_server=exchange_server,
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


# @flask_app.route(rule=<refresh-endpoint>,
#                  methods=["GET"])
def service_refresh() -> Response:
    """
    Entry point for refreshing a token from the *IAM* server.

    The expected request parameters, to be found in the body *JSON*, are:
        - user-id: identification for the reference user (alias: 'login')
        - access-token: the old, probable expíred, token to be refreshed

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <token>
        }

    :return: *Response* containing the user reference identification and the token, or *BAD REQUEST*
    """
    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args) or {}

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    token_info: dict[str, str] | None = None
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # retrieve the token
            errors: list[str] = []
            token_info = iam_refresh(iam_server=iam_server,
                                     args=args,
                                     errors=errors,
                                     logger=__IAM_LOGGER)
    result: Response
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = jsonify(token_info)
    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<token-endpoint>,
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for aquiring a token from the *IAM* server.

    The user is identified by the attribute *user-id* or "login", provided as a request parameter.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    If one or more trusted hosts have been specified for the corresponding *IAM* server, only requests
    originating from those hosts are serviced. All others requests will be refused as *UNAUTHORIZED*.

    On success, the returned *Response* will contain the following JSON:
        {
            "user-id": <reference-user-identification>,
            "access-token": <token>
        }

    :return: *Response* containing the user identification and the token, or *BAD REQUEST*, or *UNAUTHORIZED*
    """
    # initialize the return variable
    result: Response | None = None

    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args) or {}

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    errors: list[str] = []
    token_info: dict[str, str] | None = None
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # validate the requester
            trusted_hosts: list[str] = _get_iam_property(iam_server=iam_server,
                                                         attr=ServerParam.TRUSTED_HOSTS,
                                                         errors=None,
                                                         logger=__IAM_LOGGER) or []
            if not trusted_hosts or request.host in trusted_hosts:
                # retrieve the token
                errors: list[str] = []
                token_info = iam_token(iam_server=iam_server,
                                       args=args,
                                       errors=errors,
                                       logger=__IAM_LOGGER)
            else:
                if __IAM_LOGGER:
                    __IAM_LOGGER.error(msg=f"Not authorized: '{request.host}' not a trusted host")
                result = Response(response="Not authorized",
                                  status=401)
    if not result:
        if errors:
            result = Response(response="; ".join(errors),
                              status=400)
        else:
            result = jsonify(token_info)

    if __IAM_LOGGER:
        # log the response (the returned data is not logged, as it contains the token)
        __IAM_LOGGER.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<userinfo-endpoint>,
#                  methods=["GET"])
@jwt_required
def service_userinfo() -> Response:
    """
    Entry point for retrieving user data from the *IAM* server.

    The user is identified by the attribute *user-id* or "login", provided as a request parameter.

    When registering this endpoint, the name used in *Flask*'s *endpoint* parameter must be prefixed with
    the name of the *IAM* server in charge of handling this service. This prefixing is done automatically
    if the endpoint is established with a call to *iam_setup_endpoints()*.

    On success, the returned *Response* will contain a JSON with information kept by *iam_server* about *user_id*.

    :return: *Response* containing user data, or *BAD REQUEST*
    """
    # retrieve the request arguments
    args: dict[str, Any] = dict(request.args) or {}

    # log the request
    if __IAM_LOGGER:
        __IAM_LOGGER.debug(msg=f"Request {request.method}:{request.path}; {json.dumps(obj=args,
                                                                                      ensure_ascii=False)}")
    # retrieve the bearer token
    args["access-token"] = __get_bearer_token(req=request)

    errors: list[str] = []
    user_info: dict[str, str] | None = None
    with _iam_lock:
        # retrieve the IAM server
        iam_server: IamServer = _iam_server_from_endpoint(endpoint=request.endpoint,
                                                          errors=errors,
                                                          logger=__IAM_LOGGER)
        if iam_server:
            # retrieve the token
            errors: list[str] = []
            user_info = iam_userinfo(iam_server=iam_server,
                                     args=args,
                                     errors=errors,
                                     logger=__IAM_LOGGER)
    result: Response
    if errors:
        result = Response(response="; ".join(errors),
                          status=400)
    else:
        result = jsonify(user_info)
    if __IAM_LOGGER:
        # log the response
        __IAM_LOGGER.debug(msg=f"Response {result}; {json.dumps(obj=user_info,
                                                                ensure_ascii=False)}")
    return result
