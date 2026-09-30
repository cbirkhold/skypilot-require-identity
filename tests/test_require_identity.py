"""Tests for the skypilot-require-identity plugin.

The plugin is loaded through SkyPilot's own plugin loader into a FastAPI app
with the same websocket-aware wrapper the server uses, so the tests cover the
HTTP and websocket handshake paths end to end.
"""
# pylint: disable=redefined-outer-name

import fastapi
from fastapi.testclient import TestClient
import pytest
from sky.server import config as server_config
from sky.server import plugins
from starlette.websockets import WebSocketDisconnect
import yaml

import skypilot_require_identity  # pylint: disable=unused-import

HEADER = 'Tailscale-User-Login'


def _proxy_config(enabled: bool) -> server_config.ExternalProxyConfig:
    if not enabled:
        return server_config.ExternalProxyConfig(enabled=False)
    return server_config.ExternalProxyConfig(enabled=True,
                                             header_name=HEADER,
                                             header_format='plaintext')


def _build_app(monkeypatch, tmp_path, proxy_enabled: bool = True):
    config_path = tmp_path / 'plugins.yaml'
    config_path.write_text(
        yaml.safe_dump({
            'plugins': [{
                'class': 'skypilot_require_identity.RequireIdentityPlugin',
            }],
        }))
    monkeypatch.setenv(
        plugins._PLUGINS_CONFIG_ENV_VAR,  # pylint: disable=protected-access
        str(config_path))
    monkeypatch.setattr(plugins, '_PLUGINS', {})
    monkeypatch.setattr(server_config, 'load_external_proxy_config',
                        lambda: _proxy_config(proxy_enabled))

    app = fastapi.FastAPI()

    @app.get('/api/health')
    async def health():
        return {'status': 'healthy'}

    @app.get('/api/healthz')
    async def healthz():
        return {'status': 'healthy'}

    @app.get('/users/role')
    async def role():
        return {'role': 'admin'}

    @app.websocket('/kubernetes-pod-ssh-proxy')
    async def ssh_proxy(websocket: fastapi.WebSocket):
        await websocket.accept()
        await websocket.send_text('accepted')
        await websocket.close()

    plugins.load_plugins(
        plugins.ExtensionContext(context=plugins.PluginContext.UVICORN,
                                 app=app))
    return app


@pytest.fixture
def client(monkeypatch, tmp_path):
    # A non-loopback client address, like traffic from the ingress proxy.
    return TestClient(_build_app(monkeypatch, tmp_path),
                      client=('10.0.0.7', 40000))


def test_plugin_installs_middleware(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    names = [m.cls.__name__ for m in app.user_middleware]
    assert names == ['RefuseCrossSiteMiddleware', 'RequireIdentityMiddleware']
    assert len(plugins.get_plugins()) == 1


def test_plugin_refuses_to_install_without_proxy(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match='external auth proxy is disabled'):
        _build_app(monkeypatch, tmp_path, proxy_enabled=False)


def test_no_identity_is_refused(client):
    response = client.get('/users/role')
    assert response.status_code == 401
    assert response.json() == {'detail': 'Authentication required'}
    assert response.headers['cache-control'] == 'no-store'


def test_empty_header_is_refused(client):
    assert client.get('/users/role', headers={HEADER: ''}).status_code == 401


def test_header_passes(client):
    response = client.get('/users/role', headers={HEADER: 'alice@example.com'})
    assert response.status_code == 200


def test_header_name_is_case_insensitive(client):
    response = client.get('/users/role',
                          headers={HEADER.lower(): 'alice@example.com'})
    assert response.status_code == 200


def test_service_account_token_passes_to_bearer_middleware(client):
    # The plugin only checks the prefix; BearerTokenMiddleware validates the
    # token afterwards.
    response = client.get('/users/role',
                          headers={'Authorization': 'Bearer sky_token'})
    assert response.status_code == 200


def test_other_bearer_token_is_refused(client):
    response = client.get('/users/role',
                          headers={'Authorization': 'Bearer abc'})
    assert response.status_code == 401


def test_basic_auth_is_refused(client):
    response = client.get('/users/role',
                          headers={'Authorization': 'Basic dXNlcjpwYXNz'})
    assert response.status_code == 401


def test_health_passes(client):
    assert client.get('/api/health').status_code == 200


def test_health_path_is_exact(client):
    assert client.get('/api/healthz').status_code == 401
    assert client.get('/api/health/').status_code == 401


def test_dashboard_is_refused(client):
    assert client.get('/dashboard/').status_code == 401


def test_loopback_passes(monkeypatch, tmp_path):
    client = TestClient(_build_app(monkeypatch, tmp_path),
                        client=('127.0.0.1', 40000))
    assert client.get('/users/role').status_code == 200


def test_forwarded_loopback_is_refused(monkeypatch, tmp_path):
    client = TestClient(_build_app(monkeypatch, tmp_path),
                        client=('127.0.0.1', 40000))
    response = client.get('/users/role',
                          headers={'X-Forwarded-For': '10.0.0.7'})
    assert response.status_code == 401


def test_websocket_without_identity_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect('/kubernetes-pod-ssh-proxy'):
            pass
    assert exc_info.value.code == 4401


def test_websocket_with_header_is_accepted(client):
    with client.websocket_connect('/kubernetes-pod-ssh-proxy',
                                  headers={HEADER: 'alice@example.com'}) as ws:
        assert ws.receive_text() == 'accepted'


def test_websocket_with_service_account_token_is_accepted(client):
    with client.websocket_connect('/kubernetes-pod-ssh-proxy',
                                  headers={'Authorization': 'Bearer sky_token'
                                          }) as ws:
        assert ws.receive_text() == 'accepted'


def test_websocket_with_other_bearer_token_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect('/kubernetes-pod-ssh-proxy',
                                      headers={'Authorization': 'Bearer abc'}):
            pass
    assert exc_info.value.code == 4401


# Cross-site refusal. Every request below carries an identity so that only
# the cross-site rule decides.

IDENTITY = {HEADER: 'alice@example.com'}
OWN = 'testserver'


def test_same_origin_fetch_passes(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'same-origin'
                          })
    assert response.status_code == 200


def test_navigation_passes(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'none'
                          })
    assert response.status_code == 200


def test_cross_site_fetch_is_refused(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'cross-site'
                          })
    assert response.status_code == 403
    assert response.json() == {'detail': 'Cross-site request refused'}
    assert 'access-control-allow-origin' not in response.headers


def test_same_site_fetch_is_refused(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'same-site'
                          })
    assert response.status_code == 403


def test_own_origin_passes(client):
    response = client.post('/users/role',
                           headers={
                               **IDENTITY, 'Origin': f'http://{OWN}'
                           })
    # 405: the route only takes GET, so the request reached the app.
    assert response.status_code == 405


def test_own_origin_via_forwarded_host_passes(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Origin': 'https://sky.example.net',
                              'X-Forwarded-Host': 'sky.example.net'
                          })
    assert response.status_code == 200


def test_foreign_origin_is_refused(client):
    response = client.post('/workspaces/config',
                           headers={
                               **IDENTITY, 'Origin': 'https://evil.example'
                           })
    assert response.status_code == 403


def test_null_origin_is_refused(client):
    response = client.get('/users/role', headers={**IDENTITY, 'Origin': 'null'})
    assert response.status_code == 403


def test_foreign_preflight_is_refused_without_cors_headers(client):
    response = client.options(
        '/workspaces/config',
        headers={
            'Origin': 'https://evil.example',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type',
        })
    assert response.status_code == 403
    assert 'access-control-allow-origin' not in response.headers
    assert 'access-control-allow-methods' not in response.headers


def test_cli_style_request_without_browser_headers_passes(client):
    response = client.get('/users/role', headers=IDENTITY)
    assert response.status_code == 200


def test_websocket_from_foreign_origin_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
                '/kubernetes-pod-ssh-proxy',
                headers={
                    **IDENTITY, 'Origin': 'https://evil.example'
                }):
            pass
    assert exc_info.value.code == 4403


def test_websocket_from_own_origin_is_accepted(client):
    with client.websocket_connect('/kubernetes-pod-ssh-proxy',
                                  headers={
                                      **IDENTITY, 'Origin': f'http://{OWN}'
                                  }) as ws:
        assert ws.receive_text() == 'accepted'


# Top-level navigations from another site pass; everything else cross-site
# stays refused.

NAVIGATE = {'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}


def test_cross_site_navigation_passes(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'cross-site',
                              **NAVIGATE
                          })
    assert response.status_code == 200


def test_same_site_navigation_passes(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'same-site',
                              **NAVIGATE
                          })
    assert response.status_code == 200


def test_cross_site_frame_is_refused(client):
    response = client.get('/dashboard/',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'cross-site',
                              'Sec-Fetch-Mode': 'navigate',
                              'Sec-Fetch-Dest': 'iframe'
                          })
    assert response.status_code == 403


def test_cross_site_post_navigation_is_refused(client):
    # A form submission from another site. Browsers also send Origin on it,
    # so both rules refuse it; this checks the fetch-metadata rule alone.
    response = client.post('/workspaces/config',
                           headers={
                               **IDENTITY, 'Sec-Fetch-Site': 'cross-site',
                               **NAVIGATE
                           })
    assert response.status_code == 403


def test_cross_site_post_navigation_with_origin_is_refused(client):
    response = client.post('/workspaces/config',
                           headers={
                               **IDENTITY, 'Sec-Fetch-Site': 'cross-site',
                               'Origin': 'https://evil.example',
                               **NAVIGATE
                           })
    assert response.status_code == 403


def test_same_site_fetch_is_still_refused(client):
    response = client.get('/users/role',
                          headers={
                              **IDENTITY, 'Sec-Fetch-Site': 'same-site',
                              'Sec-Fetch-Mode': 'cors',
                              'Sec-Fetch-Dest': 'empty'
                          })
    assert response.status_code == 403


def test_cross_site_websocket_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
                '/kubernetes-pod-ssh-proxy',
                headers={
                    **IDENTITY, 'Sec-Fetch-Site': 'cross-site',
                    'Sec-Fetch-Mode': 'websocket',
                    'Sec-Fetch-Dest': 'websocket'
                }):
            pass
    assert exc_info.value.code == 4403
