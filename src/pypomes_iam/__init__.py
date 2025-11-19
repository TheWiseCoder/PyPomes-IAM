from .iam_actions import (
    iam_callback, iam_exchange,
    iam_login, iam_logout, iam_refresh, iam_userinfo
)
from .iam_common import (
    IamServer, ServerParam
)
from .iam_pomes import (
    iam_setup_server, iam_setup_endpoints
)
from .iam_services import (
    jwt_required, iam_setup_logger,
    service_setup_server, service_login, service_logout,
    service_refresh, service_userinfo, service_callback,
    service_exchange, service_callback_exchange
)
from .provider_pomes import (
    IamProvider, ProviderParam,
    service_get_token, provider_get_token,
    iam_setup_provider, provider_setup_endpoint, provider_setup_logger
)

__all__ = [
    # iam_actions
    "iam_callback", "iam_exchange",
    "iam_login", "iam_logout", "iam_refresh", "iam_userinfo",
    # iam_commons
    "IamServer", "ServerParam",
    # iam_pomes
    "iam_setup_server", "iam_setup_endpoints",
    # iam_services
    "jwt_required", "iam_setup_logger",
    "service_setup_server", "service_login", "service_logout",
    "service_refresh", "service_userinfo", "service_callback",
    "service_exchange", "service_callback_exchange",
    # provider_pomes
    "IamProvider", "ProviderParam",
    "service_get_token", "service_refresh", "provider_get_token",
    "iam_setup_provider", "provider_setup_endpoint", "provider_setup_logger",
]

from importlib.metadata import version
__version__ = version("pypomes_iam")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
