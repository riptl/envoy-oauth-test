#!/usr/bin/python3

import argparse
import json
from urllib.parse import urlparse
import yaml

parser = argparse.ArgumentParser(description="Generate Envoy config file")
parser.add_argument(
    "--listen_address", type=str, default="0.0.0.0", help="IP address to listen on"
)
parser.add_argument(
    "--domain", type=str, required=True, help="Domain to expose test on"
)
parser.add_argument(
    "--providers", type=str, required=True, help="Path to providers file"
)
args = parser.parse_args()


class ConfigBuilder:
    def __init__(self, domain):
        self.domain = domain
        self.config = {
            "admin": {
                "access_log_path": "/var/log/envoy/access.log",
            },
            "static_resources": {
                "secrets": [],
                "listeners": [
                    {
                        "name": "public-https",
                        "address": {
                            "socket_address": {
                                "address": args.listen_address,
                                "port_value": 443,
                            }
                        },
                        "listener_filters": [
                            {
                                "name": "envoy.filters.listener.tls_inspector",
                                "typed_config": {},
                            }
                        ],
                        "filter_chains": [],
                    }
                ],
                "clusters": [],
            },
        }

    def render_site(
        self,
        name,
        client_id,
        client_secret,
        token_endpoint,
        authorize_endpoint,
    ):
        token_secret_name = name + "-token-secret"
        hmac_secret_name = name + "-hmac"
        secrets = self.config["static_resources"]["secrets"]
        secrets.append(
            {
                "name": token_secret_name,
                "generic_secret": {"secret": {"inline_string": client_secret}},
            }
        )
        secrets.append(
            {
                "name": hmac_secret_name,
                "generic_secret": {"secret": {"inline_string": client_secret}},
            }
        )
        token_url = urlparse(token_endpoint)
        subdomain = f"{name}.{self.domain}"
        redirect_uri = f"https://{name}.{self.domain}"
        oauth_filter = {
            "name": "envoy.filters.http.oauth2",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.oauth2.v3alpha.OAuth2",
                "config": {
                    "token_endpoint": {
                        "cluster": name,
                        "uri": token_endpoint,
                        "timeout": "5s",
                    },
                    "authorization_endpoint": authorize_endpoint,
                    "redirect_uri": redirect_uri,
                    "redirect_path_matcher": {"path": {"exact": "/callback"}},
                    "signout_path": {"path": {"exact": "/signout"}},
                    "credentials": {
                        "client_id": client_id,
                        "token_secret": {"name": token_secret_name},
                        "hmac_secret": {"name": hmac_secret_name},
                    },
                },
            },
        }
        lua_filter = {
            "name": "envoy.filters.http.lua",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
                "inline_code": """
function envoy_on_request(request)
  request:respond({ [":status"] = "200" }, "OAuth success")
end
""",
            },
        }
        router_filter = {"name": "envoy.filters.http.router"}
        conn_mgr_config = {
            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
            "stat_prefix": "public",
            "codec_type": "AUTO",
            "route_config": {
                "name": "local_route",
                "virtual_hosts": [{"name": "local_service", "domains": "*"}],
            },
            "http_filters": [oauth_filter, lua_filter, router_filter],
        }
        filter_chain = {
            "filter_chain_match": {"server_names": [subdomain]},
            "filters": {
                "name": "envoy.http_connection_manager",
                "typed_config": conn_mgr_config,
            },
        }
        chains = self.config["static_resources"]["listeners"][0]["filter_chains"]
        chains.append(filter_chain)
        token_address = {
            "address": {
                "socket_address": {
                    "address": token_url.netloc,
                    "port_value": 443,
                }
            }
        }
        cluster = {
            "name": name,
            "connect_timeout": "5s",
            "type": "LOGICAL_DNS",
            "lb_policy": "ROUND_ROBIN",
            "load_assignment": {
                "cluster_name": name,
                "endpoints": [{"lb_endpoints": [{"endpoint": token_address}]}],
            },
        }
        clusters = self.config["static_resources"]["clusters"]
        clusters.append(cluster)


builder = ConfigBuilder(args.domain)

with open(args.providers, "r") as f:
    providers = yaml.safe_load(f.read())

for provider in providers:
    builder.render_site(
        name=provider["name"],
        client_id=provider["client_id"],
        client_secret=provider["client_secret"],
        token_endpoint=provider["token_endpoint"],
        authorize_endpoint=provider["authorize_endpoint"],
    )

print(json.dumps(builder.config))
