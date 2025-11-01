from .iam_actions import (
    action_callback, action_exchange,
    action_login, action_logout, action_token
)
from .iam_common import (
    IamServer, IamParam
)
from .iam_pomes import (
    iam_setup, iam_get_token
)
from .iam_services import (
     jwt_required, logger_register
)
from .provider_pomes import (
    provider_register, provider_get_token
)
from .token_pomes import (
    token_validate
)

__all__ = [
    # iam_actions
    "action_callback", "action_exchange",
    "action_login", "action_logout", "action_token",
    # iam_commons
    "IamServer", "IamParam",
    # iam_pomes
    "iam_setup", "iam_get_token",
    # iam_services
    "jwt_required", "logger_register",
    # provider_pomes
    "provider_register", "provider_get_token",
    # token_pomes
    "token_validate"
]

from importlib.metadata import version
__version__ = version("pypomes_iam")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
