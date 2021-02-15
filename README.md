# Envoy OAuth test environment

End-to-end tests for Envoy's [OAuth2 plugin](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/oauth2_filter).

Environments:

| Provider | Status | URL |
| -------- | ------ | --- |
| Amazon | ✅ Works | https://amazon.envoy-oauth.lab.terorie.dev |
| Discord | ✅ Works | https://discord.envoy-oauth.lab.terorie.dev |
| GitHub | ❌ Incompatible | https://github.envoy-oauth.lab.terorie.dev |
| GitLab | ❌ Token client timeout | https://gitlab.envoy-oauth.lab.terorie.dev |
| Google | ❌ Token client timeout | https://google.envoy-oauth.lab.terorie.dev |
| Twitch | ✅ Works | https://twitch.envoy-oauth.lab.terorie.dev |

IPv4 is unsupported.

## Issues

### Token response without `expire_in`

Root cause: Envoy RFC 6749 violation.

Tracking issue: https://github.com/envoyproxy/envoy/issues/14542

Affects: GitHub

### Token client timeout

Root cause: Unknown

The Envoy HTTP client for the token response times out connecting to the OAuth server.

```
[2021-02-15 02:24:27.444][12][debug][router] [source/common/router/router.cc:803] [C0][S14383117660753541910] upstream timeout
[2021-02-15 02:24:27.446][12][debug][pool] [source/common/conn_pool/conn_pool_base.cc:490] cancelling pending stream
[2021-02-15 02:24:27.446][12][debug][router] [source/common/router/upstream_request.cc:291] [C0][S14383117660753541910] canceled pool request
[2021-02-15 02:24:27.446][12][debug][http] [source/common/http/async_client_impl.cc:101] async http request response headers (end_stream=false):
':status', '504'
'content-length', '24'
'content-type', 'text/plain'
```

Affects: GitLab, Google
