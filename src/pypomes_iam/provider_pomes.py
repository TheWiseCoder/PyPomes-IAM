import json
import requests
import sys
from base64 import b64encode
from datetime import datetime
from enum import StrEnum
from logging import Logger
from pypomes_core import TZ_LOCAL, exc_format
from threading import Lock
from typing import Any, Final


class ProviderParam(StrEnum):
    """
    Parameters for configuring a *JWT* token provider.
    """
    URL = "url"
    USER = "user"
    PWD = "pwd"
    CUSTOM_AUTH = "custom-auth"
    HEADER_DATA = "headers-data"
    BODY_DATA = "body-data"
    ACCESS_TOKEN = "access-token"
    ACCESS_EXPIRATION = "access-expiration"
    REFRESH_TOKEN = "refresh-token"
    REFRESH_EXPIRATION = "refresh-expiration"


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
_provider_registry: Final[dict[str, dict[str, Any]]] = {}

# the lock protecting the data in '_provider_registry'
# (because it is 'Final' and set at declaration time, it can be accessed through simple imports)
_provider_lock: Final[Lock] = Lock()


def provider_register(provider_id: str,
                      auth_url: str,
                      auth_user: str,
                      auth_pwd: str,
                      custom_auth: tuple[str, str] = None,
                      headers_data: dict[str, str] = None,
                      body_data: dict[str, str] = None) -> None:
    """
    Register an external authentication token provider.

    If specified, *custom_auth* provides key names for sending credentials (username and password, in this order)
    as key-value pairs in the body of the request. Otherwise, the external provider *provider_id* uses the standard
    HTTP Basic Authorization scheme, wherein the credentials are B64-encoded and sent in the request headers.

    Optional constant key-value pairs (such as ['Content-Type', 'application/x-www-form-urlencoded']), to be
    added to the request headers, may be specified in *headers_data*. Likewise, optional constant key-value pairs
    (such as ['grant_type', 'client_credentials']), to be added to the request body, may be specified in *body_data*.

    :param provider_id: the provider's identification
    :param auth_url: the url to request authentication tokens with
    :param auth_user: the basic authorization user
    :param auth_pwd: the basic authorization password
    :param custom_auth: optional key names for sending the credentials as key-value pairs in the body of the request
    :param headers_data: optional key-value pairs to be added to the request headers
    :param body_data: optional key-value pairs to be added to the request body
    """
    global _provider_registry

    with _provider_lock:
        _provider_registry[provider_id] = {
            ProviderParam.URL: auth_url,
            ProviderParam.USER: auth_user,
            ProviderParam.PWD: auth_pwd,
            ProviderParam.CUSTOM_AUTH: custom_auth,
            ProviderParam.HEADER_DATA: headers_data,
            ProviderParam.BODY_DATA: body_data,
            ProviderParam.ACCESS_TOKEN: None,
            ProviderParam.ACCESS_EXPIRATION: 0,
            ProviderParam.REFRESH_TOKEN: None,
            ProviderParam.REFRESH_EXPIRATION: 0
        }


def provider_get_token(provider_id: str,
                       errors: list[str] = None,
                       logger: Logger = None) -> str | None:
    """
    Obtain an authentication token from the external provider *provider_id*.

    :param provider_id: the provider's identification
    :param errors: incidental error messages
    :param logger: optional logger
    """
    global _provider_registry  # noqa: PLW0602

    # initialize the return variable
    result: str | None = None

    err_msg: str | None = None
    with _provider_lock:
        provider: dict[str, Any] = _provider_registry.get(provider_id)
        if provider:
            now: float = datetime.now(tz=TZ_LOCAL).timestamp()
            if now > provider.get(ProviderParam.ACCESS_EXPIRATION):
                user: str = provider.get(ProviderParam.USER)
                pwd: str = provider.get(ProviderParam.PWD)
                headers_data: dict[str, str] = provider.get(ProviderParam.HEADER_DATA) or {}
                body_data: dict[str, str] = provider.get(ProviderParam.BODY_DATA) or {}
                custom_auth: tuple[str, str] = provider.get(ProviderParam.CUSTOM_AUTH)
                if custom_auth:
                    body_data[custom_auth[0]] = user
                    body_data[custom_auth[1]] = pwd
                else:
                    enc_bytes: bytes = b64encode(f"{user}:{pwd}".encode())
                    headers_data["Authorization"] = f"Basic {enc_bytes.decode()}"
                url: str = provider.get(ProviderParam.URL)
                if logger:
                    logger.debug(msg=f"POST {url}, {json.dumps(obj=body_data,
                                                               ensure_ascii=False)}")
                try:
                    # typical return on a token request:
                    # {
                    #   "token_type": "Bearer",
                    #   "access_token": <str>,
                    #   "expires_in": <number-of-seconds>,
                    #   optional data:
                    #   "refresh_token": <str>,
                    #   "refresh_expires_in": <number-of-seconds>
                    # }
                    response: requests.Response = requests.post(url=url,
                                                                data=body_data,
                                                                headers=headers_data,
                                                                timeout=None)
                    if response.status_code < 200 or response.status_code >= 300:
                        # request resulted in error, report the problem
                        err_msg = (f"POST failure, "
                                   f"status {response.status_code}, reason {response.reason}")
                    else:
                        # request succeeded
                        if logger:
                            logger.debug(msg=f"POST success, status {response.status_code}")
                        reply: dict[str, Any] = response.json()
                        provider[ProviderParam.ACCESS_TOKEN] = reply.get("access_token")
                        provider[ProviderParam.ACCESS_EXPIRATION] = now + int(reply.get("expires_in"))
                        if reply.get(ProviderParam.REFRESH_TOKEN):
                            provider[ProviderParam.REFRESH_TOKEN] = reply["refresh_token"]
                            if reply.get("refresh_expires_in"):
                                provider[ProviderParam.REFRESH_EXPIRATION] = now + int(reply.get("refresh_expires_in"))
                            else:
                                provider[ProviderParam.REFRESH_EXPIRATION] = sys.maxsize
                        if logger:
                            logger.debug(msg=f"POST {url}: status {response.status_code}")
                except Exception as e:
                    # the operation raised an exception
                    err_msg = exc_format(exc=e,
                                         exc_info=sys.exc_info())
                    err_msg = f"POST error, '{err_msg}'"
        else:
            err_msg: str = f"Provider '{provider_id}' not registered"

    if err_msg:
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)
    else:
        result = provider.get(ProviderParam.ACCESS_TOKEN)

    return result


