# skypilot-require-identity

A SkyPilot API server plugin that refuses requests carrying no identity.

## Why

With `auth.external_proxy` enabled, SkyPilot trusts the proxy in front of it to
authenticate every request. A request that arrives without the identity header
is not refused: `AuthProxyMiddleware` passes it through, `RBACMiddleware` skips
a request with no auth user, and the request runs as the server's own root
account, an admin, as a result. Websocket endpoints accept such connections too,
for instance `/kubernetes-pod-ssh-proxy`.

Any proxy that forwards a request it did not authenticate exposes this. Behind
a Tailscale ingress, for example, a tagged device has no user identity, so the
ingress forwards its requests without the header. This plugin makes the server
refuse such requests itself, so that the proxy's access rules are not the only
control. Defense in depth.

## How

The plugin adds a middleware to the API server. Plugins install after the core
middleware stack, so it is the outermost middleware and runs before SkyPilot's
authentication middleware. It cannot read `request.state.auth_user` and checks
the request itself instead. A request passes when at least one of the following
is true:

1. it carries a non-empty value in the configured identity header
   (`auth.external_proxy.header_name`), which the proxy sets from the caller's
   verified identity and strips from the caller's own request;
2. it carries an `Authorization: Bearer sky_...` service account token, which
   SkyPilot's `BearerTokenMiddleware` validates afterwards and refuses with 401
   when invalid;
3. it comes from loopback with no forwarding headers, as the server's own
   processes do;
4. its path is exactly `/api/health`, which the kubelet probes call on the pod
   directly.

Any other request gets a HTTP 401 `{"detail": "Authentication required"}` with
`Cache-Control: no-store`. A websocket handshake is refused the same way,
uvicorn reports the refusal as HTTP 403 on the handshake.

The plugin refuses to install, and the server does not start, when the external
auth proxy is disabled, since the identity header then has no meaning.

Two assumptions must hold for the checks to work:

- the proxy strips identity headers a caller sends, and it is the only network
  path to the server. Enforce the second with a network policy;
- the proxy is not a sidecar in the server's pod. A sidecar would connect over
  loopback and pass check 3. Many proxies set `X-Forwarded-For`, which makes a
  loopback request non-loopback, but do not rely on that alone.

## Install

The plugin is a Python package with no dependencies of its own. It is installed
into the Python environment that runs the API server, next to the `skypilot`
package that is already there, and enabled through SkyPilot's plugins config:

```yaml
plugins:
  - class: skypilot_require_identity.RequireIdentityPlugin
```

The server reads that file from `~/.sky/plugins.yaml`, or from the path in
`SKYPILOT_SERVER_PLUGINS_CONFIG`. The plugin only loads in the API server's
uvicorn context, so it does not affect the request executors or the jobs and
serve controllers.

### Pin what you install

Each release carries a wheel and its SHA-256 in `SHA256SUMS`. Install it
through a requirements file in pip's hash-checking mode, which refuses the
file if a single byte differs, so a moved tag or a replaced asset fails the
install instead of running:

```
# requirements.txt
skypilot-require-identity @ https://github.com/cbirkhold/skypilot-require-identity/releases/download/v0.1.0/skypilot_require_identity-0.1.0-py3-none-any.whl \
    --hash=sha256:<digest from the release's SHA256SUMS>
```

```bash
pip install --no-cache-dir --no-deps --require-hashes -r requirements.txt
```

`--no-deps` because the package has none, and hash mode would otherwise demand
a digest for anything pulled in. A git URL cannot be used here: pip refuses
version control sources in hash-checking mode, and a tag can be moved.

The wheel is built reproducibly, so the digest can be checked without trusting
the release: check out the tag, build with the commit's timestamp, and compare.

```bash
git checkout v0.1.0
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python -m build --wheel
sha256sum dist/*.whl
```

Each wheel also has a GitHub build provenance attestation tying it to the
workflow run that built it:

```bash
gh attestation verify skypilot_require_identity-0.1.0-py3-none-any.whl \
    --repo cbirkhold/skypilot-require-identity
```

### With the Helm chart, no custom image

The chart runs `apiService.preDeployHook` inside the API server container
before the server starts, which is where the package is installed. A ConfigMap
provides the plugins config, and an environment variable points the server at
it. The config cannot go under `/root/.sky`, because the chart mounts a
persistent volume there.

```bash
kubectl create configmap skypilot-plugins -n skypilot \
    --from-file=plugins.yaml --from-file=requirements.txt
```

```yaml
# values.yaml
apiService:
  preDeployHook: |-
    pip install --no-cache-dir --no-deps --require-hashes -r /etc/skypilot/requirements.txt
  extraEnvs:
    - name: SKYPILOT_SERVER_PLUGINS_CONFIG
      value: /etc/skypilot/plugins.yaml
  extraVolumes:
    - name: skypilot-plugins
      configMap:
        name: skypilot-plugins
  extraVolumeMounts:
    - name: skypilot-plugins
      mountPath: /etc/skypilot/plugins.yaml
      subPath: plugins.yaml
    - name: skypilot-plugins
      mountPath: /etc/skypilot/requirements.txt
      subPath: requirements.txt
```

The hook runs on every pod start and needs network access to the package
source. If the chart already sets a plugins config, merge the entry above into
it instead of adding a second file.

### With a custom image

For an air-gapped installation, or to avoid installing at pod start, build an
image from the stock one:

```dockerfile
FROM berkeleyskypilot/skypilot:0.13.0
COPY plugins.yaml requirements.txt /etc/skypilot/
RUN pip install --no-cache-dir --no-deps --require-hashes -r /etc/skypilot/requirements.txt
ENV SKYPILOT_SERVER_PLUGINS_CONFIG=/etc/skypilot/plugins.yaml
```

Then set `apiService.image` to that image.

## Verify

Run the unit tests inside the stock image, which is the target environment:

```bash
docker run --rm -v "$PWD:/plugin:ro" berkeleyskypilot/skypilot:0.13.0 bash -c \
  'pip install -q pytest && cd /plugin && PYTHONPATH=/plugin python -m pytest -q tests'
```

After deployment, from a client the proxy passes through without an identity:

```bash
curl -si https://<api-server>/users/role          # expect 401
curl -si https://<api-server>/workspaces/config   # expect 401
curl -si https://<api-server>/api/health          # expect 200
```

From a client with an identity, `sky api info` and a small job must still work,
and `sky ssh` to a Kubernetes cluster must still open its websocket.

## Supported SkyPilot versions

The plugin uses SkyPilot's plugin API (`sky.server.plugins.BasePlugin`), the
`websocket_aware` wrapper from `sky.server.middleware_utils`,
`sky.server.auth.loopback.is_loopback_request`, and
`sky.server.config.load_external_proxy_config`.

| SkyPilot | Status |
|---|---|
| 0.13.0 | Verified: unit tests and checks against the running server pass |
| master | The four interfaces above exist; not run |

"Verified" means against the `berkeleyskypilot/skypilot` image of that
version, by the digest the test workflow pins. For 0.13.0 that is
`sha256:3bc8bf8f4d83023bae2260b15d01f7581fa2c3e225b75983d92c7f781252662d`.

Versions before 0.13.0 are not supported. The package declares no dependency
on `skypilot`, because the server image already provides it, under the name
`skypilot` or `skypilot-nightly`, and a dependency would pull in a second copy.

## Upgrading SkyPilot

An import failure aborts server start, so a breaking upgrade fails with due
notice. After an upgrade, rerun the unit tests against the new image and the
post-deployment checks above.
