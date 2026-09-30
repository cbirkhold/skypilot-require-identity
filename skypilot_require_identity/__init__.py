"""SkyPilot API server plugin that refuses requests carrying no identity.

With an external auth proxy, SkyPilot runs a request that no middleware
identified as the server's own root account, an admin. This plugin installs a
websocket-aware middleware that refuses such a request with HTTP 401, or close
code 4401 for a websocket handshake, unless it carries the proxy's identity
header or a ``sky_`` bearer token, comes from loopback, or is the
``/api/health`` probe.

See README.md for the full rule, the assumptions it relies on, and how to
install and verify the plugin.
"""

from typing import Optional

import fastapi
import starlette.middleware.base

from sky import sky_logging
from sky.server import config as server_config
from sky.server import middleware_utils
from sky.server import plugins
from sky.server.auth import loopback

logger = sky_logging.init_logger(__name__)

__version__ = '0.1.0'

_HEALTH_PATH = '/api/health'
_SERVICE_ACCOUNT_TOKEN_PREFIX = 'sky_'


def _has_service_account_token(request: fastapi.Request) -> bool:
    auth_header = request.headers.get('authorization')
    if not auth_header:
        return False
    scheme, _, token = auth_header.partition(' ')
    return (scheme.lower() == 'bearer' and
            token.startswith(_SERVICE_ACCOUNT_TOKEN_PREFIX))


@middleware_utils.websocket_aware
class RequireIdentityMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    """Refuses a request that carries no identity. See README.md."""

    # pylint: disable=redefined-outer-name
    def __init__(self, app, header_name: str):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: fastapi.Request, call_next):
        if request.headers.get(self.header_name):
            return await call_next(request)
        if _has_service_account_token(request):
            return await call_next(request)
        if loopback.is_loopback_request(request):
            return await call_next(request)
        if request.url.path == _HEALTH_PATH:
            return await call_next(request)
        return fastapi.responses.JSONResponse(
            status_code=401,
            headers={
                # Prevent CDNs/browsers from caching auth failures on
                # cacheable URLs (e.g. /dashboard/_next/...).
                'Cache-Control': 'no-store',
            },
            content={'detail': 'Authentication required'})


class RequireIdentityPlugin(plugins.BasePlugin):
    """Installs RequireIdentityMiddleware into the API server."""

    load_contexts = frozenset({plugins.PluginContext.UVICORN})

    @property
    def name(self) -> Optional[str]:
        return 'skypilot-require-identity'

    @property
    def version(self) -> Optional[str]:
        return __version__

    def install(self, extension_context: plugins.ExtensionContext):
        proxy_config = server_config.load_external_proxy_config()
        if not proxy_config.enabled:
            raise ValueError(
                f'{self.name}: the external auth proxy is disabled '
                '(auth.external_proxy.enabled), so there is no identity '
                'header to require. Enable the proxy or remove the plugin.')
        app = extension_context.app
        if app is None:
            raise ValueError(f'{self.name}: no FastAPI app in the extension '
                             'context')
        app.add_middleware(RequireIdentityMiddleware,
                           header_name=proxy_config.header_name)
        logger.info(f'{self.name}: refusing requests without the '
                    f'{proxy_config.header_name} header, a sky_ bearer '
                    'token, or a loopback source')
