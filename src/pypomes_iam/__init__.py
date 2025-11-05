from .iam_actions import (
    action_callback, action_exchange,
    action_login, action_logout, action_token
)
from .iam_common import (
    IamServer, IamParam
)
from .iam_pomes import (
    iam_setup_server, iam_setup_endpoints
)
from .iam_services import (
    jwt_required, iam_setup_logger,
    service_login, service_logout, service_callback,
    service_exchange, service_callback_and_exchange, service_token
)
from .provider_pomes import (
    provider_setup_server, provider_setup_endpoint, provider_setup_logger,
    service_jwt_token, action_jwt_token
)
from .token_pomes import (
    token_get_claims, token_get_values, token_validate
)

__all__ = [
    # iam_actions
    "action_callback", "action_exchange",
    "action_login", "action_logout", "action_token",
    # iam_commons
    "IamServer", "IamParam",
    # iam_pomes
    "iam_setup_server", "iam_setup_endpoints",
    # iam_services
    "jwt_required", "iam_setup_logger",
    "service_login", "service_logout", "service_callback",
    "service_exchange", "service_callback_and_exchange", "service_token",
    # provider_pomes
    "provider_setup_server", "action_jwt_token",
    # token_pomes
    "token_get_claims", "token_get_values", "token_validate"
]

from importlib.metadata import version
__version__ = version("pypomes_iam")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
