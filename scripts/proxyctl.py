#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import contextlib
import getpass
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import tomllib

DEFAULT_CONFIG_FILE = "proxy.toml"
DEFAULT_OUTPUT_DIR = ".proxy"
DEFAULT_IMAGE = "qmcgaw/gluetun:v3"
DEFAULT_BIND_ADDRESS = "127.0.0.1"
DEFAULT_CONTROL_PORT_START = 19000
SECRETS_DIR_NAME = "secrets"


@dataclass
class ProxyConfig:
    project_name: str
    timezone: str
    output_dir: Path
    image: str
    protocol: str
    mssfix: int
    http_proxy: bool
    dot: bool
    dns_address: str | None
    health_target_address: str | None
    bind_address: str
    local_networks: list[str]
    enable_control_api: bool
    control_port_start: int
    provider: dict[str, Any]
    tunnels: list[dict[str, Any]]


@dataclass
class GenerationResult:
    compose_path: Path
    endpoints: list[tuple[str, str]]
    output_dir: Path


def abort(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        abort(f"missing config file: {path}")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        abort(f"invalid TOML in {path}: {exc}")
    if not isinstance(raw, dict):
        abort(f"invalid config root in {path}")
    return raw


def require_table(raw: dict[str, Any], key: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
    value = raw.get(key, default if default is not None else {})
    if not isinstance(value, dict):
        abort(f"[{key}] must be a TOML table")
    return value


def require_list_of_tables(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        abort(f"[[{key}]] must exist and contain at least one tunnel")
    for item in value:
        if not isinstance(item, dict):
            abort(f"each [[{key}]] entry must be a table")
    return value


def require_string(obj: dict[str, Any], key: str, *, where: str, default: str | None = None) -> str:
    value = obj.get(key, default)
    if not isinstance(value, str) or not value.strip():
        abort(f"{where}.{key} must be a non-empty string")
    return value.strip()


def require_bool(obj: dict[str, Any], key: str, *, where: str, default: bool) -> bool:
    value = obj.get(key, default)
    if not isinstance(value, bool):
        abort(f"{where}.{key} must be true or false")
    return value


def require_int(
    obj: dict[str, Any],
    key: str,
    *,
    where: str,
    default: int | None = None,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    value = obj.get(key, default)
    if not isinstance(value, int):
        abort(f"{where}.{key} must be an integer")
    if min_value is not None and value < min_value:
        abort(f"{where}.{key} must be >= {min_value}")
    if max_value is not None and value > max_value:
        abort(f"{where}.{key} must be <= {max_value}")
    return value


def optional_string(obj: dict[str, Any], key: str, *, where: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        abort(f"{where}.{key} must be a non-empty string when provided")
    return value.strip()


def optional_table(obj: dict[str, Any], key: str, *, where: str) -> dict[str, Any]:
    value = obj.get(key, {})
    if not isinstance(value, dict):
        abort(f"{where}.{key} must be a table")
    return value


def optional_string_list(obj: dict[str, Any], key: str, *, where: str) -> list[str]:
    value = obj.get(key, [])
    if not isinstance(value, list):
        abort(f"{where}.{key} must be a list of strings")
    items: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            abort(f"{where}.{key}[{idx}] must be a non-empty string")
        items.append(item.strip())
    return items


def coerce_str(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def coerce_int(value: Any, default: int) -> int:
    if isinstance(value, int):
        return value
    return default


def coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def coerce_string_list(value: Any, default: list[str] | None = None) -> list[str]:
    if default is None:
        default = []
    if not isinstance(value, list):
        return list(default)
    items: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            items.append(item.strip())
    return items if items else list(default)


def coerce_string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            continue
        if isinstance(item, (str, int, float, bool)):
            result[key.strip().upper()] = coerce_env_value(item)
    return result


def default_config_template(provider_type: str = "nordvpn") -> dict[str, Any]:
    provider_type = provider_type if provider_type in {"nordvpn", "gluetun"} else "nordvpn"
    if provider_type == "nordvpn":
        provider: dict[str, Any] = {
            "type": "nordvpn",
            "username": "NORDVPN_SERVICE_USERNAME",
            "password": "NORDVPN_SERVICE_PASSWORD",
            "env": {},
            "secrets": {},
        }
    else:
        provider = {
            "type": "gluetun",
            "service": "surfshark",
            "username": "SERVICE_USERNAME",
            "password": "SERVICE_PASSWORD",
            "env": {},
            "secrets": {},
        }
    return {
        "project": {
            "name": "vpn-proxy",
            "timezone": "UTC",
            "output_dir": ".proxy",
            "local_networks": ["192.168.0.0/16", "172.16.0.0/12"],
        },
        "defaults": {
            "image": DEFAULT_IMAGE,
            "protocol": "udp",
            "mssfix": 1400,
            "http_proxy": True,
            "dot": False,
            "bind_address": "127.0.0.1",
            "dns_address": "103.86.96.100",
            "health_target_address": "103.86.96.100:53",
            "enable_control_api": False,
            "control_port_start": 19000,
        },
        "provider": provider,
        "tunnel_pool": {
            "count": 2,
            "regions": ["Finland", "Netherlands"],
            "selector": "country",
            "name_prefix": "proxy",
            "port_start": 8111,
        },
    }


def load_wizard_seed(path: Path, provider_type: str = "nordvpn") -> dict[str, Any]:
    seed = default_config_template(provider_type=provider_type)
    if not path.exists():
        return seed

    raw = read_toml(path)
    project = raw.get("project") if isinstance(raw.get("project"), dict) else {}
    defaults = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
    provider = raw.get("provider") if isinstance(raw.get("provider"), dict) else {}
    tunnels = raw.get("tunnels") if isinstance(raw.get("tunnels"), list) else []
    tunnel_pool = raw.get("tunnel_pool") if isinstance(raw.get("tunnel_pool"), dict) else {}

    seed["project"]["name"] = coerce_str(project.get("name"), seed["project"]["name"])
    seed["project"]["timezone"] = coerce_str(project.get("timezone"), seed["project"]["timezone"])
    seed["project"]["output_dir"] = coerce_str(project.get("output_dir"), seed["project"]["output_dir"])
    seed["project"]["local_networks"] = coerce_string_list(project.get("local_networks"), seed["project"]["local_networks"])

    seed["defaults"]["image"] = coerce_str(defaults.get("image"), seed["defaults"]["image"])
    seed["defaults"]["protocol"] = coerce_str(defaults.get("protocol"), seed["defaults"]["protocol"])
    seed["defaults"]["mssfix"] = coerce_int(defaults.get("mssfix"), seed["defaults"]["mssfix"])
    seed["defaults"]["http_proxy"] = coerce_bool(defaults.get("http_proxy"), seed["defaults"]["http_proxy"])
    seed["defaults"]["dot"] = coerce_bool(defaults.get("dot"), seed["defaults"]["dot"])
    seed["defaults"]["bind_address"] = coerce_str(defaults.get("bind_address"), seed["defaults"]["bind_address"])
    seed["defaults"]["dns_address"] = coerce_str(defaults.get("dns_address"), seed["defaults"]["dns_address"])
    seed["defaults"]["health_target_address"] = coerce_str(
        defaults.get("health_target_address"), seed["defaults"]["health_target_address"]
    )
    seed["defaults"]["enable_control_api"] = coerce_bool(
        defaults.get("enable_control_api"), seed["defaults"]["enable_control_api"]
    )
    seed["defaults"]["control_port_start"] = coerce_int(
        defaults.get("control_port_start"), seed["defaults"]["control_port_start"]
    )

    loaded_provider_type = coerce_str(provider.get("type"), seed["provider"]["type"]).lower()
    if loaded_provider_type in {"nordvpn", "gluetun"}:
        seed = default_config_template(provider_type=loaded_provider_type) | {
            "project": seed["project"],
            "defaults": seed["defaults"],
            "tunnel_pool": seed["tunnel_pool"],
        }
        seed["provider"]["type"] = loaded_provider_type
    seed["provider"]["env"] = coerce_string_dict(provider.get("env"))
    seed["provider"]["secrets"] = coerce_string_dict(provider.get("secrets"))
    if seed["provider"]["type"] == "nordvpn":
        seed["provider"]["username"] = coerce_str(provider.get("username"), seed["provider"]["username"])
        seed["provider"]["password"] = coerce_str(provider.get("password"), seed["provider"]["password"])
    else:
        seed["provider"]["service"] = coerce_str(provider.get("service"), seed["provider"].get("service", "surfshark"))
        seed["provider"]["username"] = coerce_str(provider.get("username"), seed["provider"]["username"])
        seed["provider"]["password"] = coerce_str(provider.get("password"), seed["provider"]["password"])

    if tunnel_pool:
        seed["tunnel_pool"]["count"] = coerce_int(tunnel_pool.get("count"), seed["tunnel_pool"]["count"])
        seed["tunnel_pool"]["regions"] = coerce_string_list(tunnel_pool.get("regions"), seed["tunnel_pool"]["regions"])
        selector = coerce_str(tunnel_pool.get("selector"), seed["tunnel_pool"]["selector"]).lower()
        seed["tunnel_pool"]["selector"] = selector if selector in {"country", "region"} else "country"
        seed["tunnel_pool"]["name_prefix"] = coerce_str(
            tunnel_pool.get("name_prefix"), seed["tunnel_pool"]["name_prefix"]
        )
        seed["tunnel_pool"]["port_start"] = coerce_int(tunnel_pool.get("port_start"), seed["tunnel_pool"]["port_start"])
        return seed

    if tunnels:
        regions: list[str] = []
        selector = "country"
        for idx, tunnel in enumerate(tunnels):
            if not isinstance(tunnel, dict):
                continue
            country = coerce_str(tunnel.get("country"), "")
            region = coerce_str(tunnel.get("region"), "")
            if region:
                selector = "region"
            regions.append(region or country or f"region-{idx + 1}")
        seed["tunnel_pool"]["count"] = len(regions) if regions else seed["tunnel_pool"]["count"]
        if regions:
            seed["tunnel_pool"]["regions"] = regions
        seed["tunnel_pool"]["selector"] = selector
        ports = [t.get("port") for t in tunnels if isinstance(t, dict) and isinstance(t.get("port"), int)]
        if ports:
            seed["tunnel_pool"]["port_start"] = min(ports)

    return seed


def prompt_string(label: str, *, default: str | None = None, allow_empty: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        raw = input(f"{label}{suffix}: ").strip()
        if not raw:
            if default is not None:
                return default
            if allow_empty:
                return ""
            print("Value required.")
            continue
        return raw


def prompt_string_keep_current(label: str, *, current: str | None = None) -> str:
    while True:
        suffix = " [Enter=keep current]" if current else ""
        raw = input(f"{label}{suffix}: ").strip()
        if raw:
            return raw
        if current:
            return current
        print("Value required.")


def prompt_optional_string(label: str, *, default: str | None = None) -> str | None:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{label}{suffix} (Enter=keep, -=clear): ").strip()
    if raw == "":
        return default
    if raw == "-":
        return None
    return raw


def prompt_secret(label: str, *, default: str | None = None) -> str:
    has_default = bool(default)
    while True:
        suffix = " [Enter=keep current]" if has_default else ""
        raw = getpass.getpass(f"{label}{suffix}: ").strip()
        if not raw and has_default and default is not None:
            return default
        if not raw:
            print("Value required.")
            continue
        return raw


def prompt_int(label: str, *, default: int, min_value: int, max_value: int) -> int:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if raw == "":
            return default
        try:
            value = int(raw)
        except ValueError:
            print("Enter a valid integer.")
            continue
        if value < min_value or value > max_value:
            print(f"Enter a value between {min_value} and {max_value}.")
            continue
        return value


def prompt_bool(label: str, *, default: bool) -> bool:
    prompt = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{label} [{prompt}]: ").strip().lower()
        if raw == "":
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Enter y or n.")


def prompt_choice(label: str, choices: list[str], *, default: str) -> str:
    options = ", ".join(f"{idx + 1}) {choice}" for idx, choice in enumerate(choices))
    print(f"{label}: {options}")
    while True:
        raw = input(f"Choose [{default}]: ").strip().lower()
        if raw == "":
            return default
        if raw.isdigit():
            index = int(raw) - 1
            if 0 <= index < len(choices):
                return choices[index]
        for choice in choices:
            if raw == choice.lower():
                return choice
        print("Pick a valid option.")


def parse_csv_list(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def is_placeholder_credential(value: str, *, kind: str) -> bool:
    cleaned = value.strip().upper()
    if kind == "username":
        return cleaned in {"", "NORDVPN_SERVICE_USERNAME", "SERVICE_USERNAME", "USERNAME"}
    if kind == "password":
        return cleaned in {"", "NORDVPN_SERVICE_PASSWORD", "SERVICE_PASSWORD", "PASSWORD"}
    return cleaned == ""


def expand_region_list(regions: list[str], count: int) -> list[str]:
    base = [region for region in regions if region]
    if not base:
        base = ["Finland", "Netherlands", "Switzerland"]
    if count <= len(base):
        return base[:count]
    out = list(base)
    idx = 0
    while len(out) < count:
        out.append(base[idx % len(base)])
        idx += 1
    return out


def prompt_csv_list(label: str, *, default: list[str] | None = None) -> list[str]:
    shown_default = ", ".join(default or [])
    suffix = f" [{shown_default}]" if shown_default else ""
    raw = input(f"{label}{suffix} (comma list, Enter=keep, -=clear): ").strip()
    if raw == "":
        return list(default or [])
    if raw == "-":
        return []
    return parse_csv_list(raw)


def parse_env_kv(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not raw.strip():
        return values
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    for part in parts:
        if "=" not in part:
            raise ValueError(f"invalid KEY=VALUE entry: '{part}'")
        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()
        if not key or not re.match(r"^[A-Z_][A-Z0-9_]*$", key):
            raise ValueError(f"invalid env key '{key}' (must match [A-Z_][A-Z0-9_]*)")
        values[key] = value
    return values


def prompt_env_map(label: str, *, default: dict[str, str] | None = None) -> dict[str, str]:
    default = default or {}
    shown_default = ", ".join(f"{key}={value}" for key, value in sorted(default.items()))
    while True:
        suffix = f" [{shown_default}]" if shown_default else ""
        raw = input(f"{label}{suffix} (KEY=VALUE comma list, Enter=keep, -=clear): ").strip()
        if raw == "":
            return dict(default)
        if raw == "-":
            return {}
        try:
            return parse_env_kv(raw)
        except ValueError as exc:
            print(str(exc))


def format_toml_string(value: str) -> str:
    return json.dumps(value)


def format_toml_bool(value: bool) -> str:
    return "true" if value else "false"


def format_toml_list(values: list[str]) -> str:
    return "[" + ", ".join(format_toml_string(value) for value in values) + "]"


def render_config_toml(config: dict[str, Any]) -> str:
    project = config["project"]
    defaults = config["defaults"]
    provider = config["provider"]
    tunnel_pool = config["tunnel_pool"]

    lines: list[str] = []
    lines.extend(
        [
            "[project]",
            f'name = {format_toml_string(project["name"])}',
            f'timezone = {format_toml_string(project["timezone"])}',
            f'output_dir = {format_toml_string(project["output_dir"])}',
            f'local_networks = {format_toml_list(project["local_networks"])}',
            "",
            "[defaults]",
            f'image = {format_toml_string(defaults["image"])}',
            f'protocol = {format_toml_string(defaults["protocol"])}',
            f"mssfix = {defaults['mssfix']}",
            f"http_proxy = {format_toml_bool(defaults['http_proxy'])}",
            f"dot = {format_toml_bool(defaults['dot'])}",
            f'bind_address = {format_toml_string(defaults["bind_address"])}',
        ]
    )
    if defaults.get("dns_address"):
        lines.append(f'dns_address = {format_toml_string(defaults["dns_address"])}')
    if defaults.get("health_target_address"):
        lines.append(f'health_target_address = {format_toml_string(defaults["health_target_address"])}')
    lines.extend(
        [
            f"enable_control_api = {format_toml_bool(defaults['enable_control_api'])}",
            f"control_port_start = {defaults['control_port_start']}",
            "",
            "[provider]",
            f'type = {format_toml_string(provider["type"])}',
        ]
    )
    if provider["type"] == "nordvpn":
        lines.append(f'username = {format_toml_string(provider["username"])}')
        lines.append(f'password = {format_toml_string(provider["password"])}')
    else:
        lines.append(f'service = {format_toml_string(provider["service"])}')
        if provider.get("username"):
            lines.append(f'username = {format_toml_string(provider["username"])}')
        if provider.get("password"):
            lines.append(f'password = {format_toml_string(provider["password"])}')

    if provider.get("env"):
        lines.extend(["", "[provider.env]"])
        for key, value in sorted(provider["env"].items()):
            lines.append(f"{key} = {format_toml_string(value)}")

    if provider.get("secrets"):
        lines.extend(["", "[provider.secrets]"])
        for key, value in sorted(provider["secrets"].items()):
            lines.append(f"{key} = {format_toml_string(value)}")

    lines.extend(
        [
            "",
            "[tunnel_pool]",
            f"count = {tunnel_pool['count']}",
            f"regions = {format_toml_list(tunnel_pool['regions'])}",
            f"selector = {format_toml_string(tunnel_pool['selector'])}",
            f"name_prefix = {format_toml_string(tunnel_pool['name_prefix'])}",
            f"port_start = {tunnel_pool['port_start']}",
        ]
    )

    return "\n".join(lines) + "\n"


def is_interactive_session() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def run_config_wizard(seed_config: dict[str, Any], *, mode: str) -> dict[str, Any]:
    if not is_interactive_session():
        abort("wizard requires an interactive terminal (use `init --template` for non-interactive setup)")

    config = copy.deepcopy(seed_config)
    provider = config["provider"]
    tunnel_pool = config["tunnel_pool"]

    print(f"\nVPN Proxy Wizard ({mode})")
    print("Essentials only. Advanced settings stay in proxy.toml.\n")

    print("VPN provider mode:")
    print("1) nordvpn = simple NordVPN flow using manual service credentials")
    print("2) gluetun = advanced mode for other providers (for example Surfshark/AirVPN/PIA)")
    provider_type = prompt_choice("Select provider mode", ["nordvpn", "gluetun"], default=provider["type"])
    if provider_type != provider["type"]:
        fresh_provider = default_config_template(provider_type=provider_type)["provider"]
        fresh_provider["env"] = provider.get("env", {})
        fresh_provider["secrets"] = provider.get("secrets", {})
        provider = fresh_provider
        config["provider"] = provider
    provider["type"] = provider_type

    if provider_type == "nordvpn":
        print("NordVPN: use manual service credentials (not account email/password).")
        print("Nord Account -> NordVPN -> Manual setup -> Set up NordVPN manually -> Service Credentials")
        print("https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/service-credentials/")
        while True:
            username = prompt_string_keep_current(
                "NordVPN service username",
                current=provider.get("username"),
            )
            if not is_placeholder_credential(username, kind="username"):
                provider["username"] = username
                break
            print("Enter a real NordVPN service username.")
        while True:
            password = prompt_secret(
                "NordVPN service password",
                default=provider.get("password"),
            )
            if not is_placeholder_credential(password, kind="password"):
                provider["password"] = password
                break
            print("Enter a real NordVPN service password.")
        provider.pop("service", None)
    else:
        provider["service"] = prompt_string("Provider service name (as expected by gluetun)", default=provider.get("service", "surfshark"))
        use_auth = prompt_bool(
            "Use username/password auth",
            default=bool(provider.get("username") and provider.get("password")),
        )
        if use_auth:
            provider["username"] = prompt_string("Provider username", default=provider.get("username"))
            provider["password"] = prompt_secret("Provider password", default=provider.get("password"))
        else:
            provider.pop("username", None)
            provider.pop("password", None)
    provider.setdefault("env", {})
    provider.setdefault("secrets", {})

    tunnel_pool["count"] = prompt_int(
        "Number of tunnels",
        default=max(1, coerce_int(tunnel_pool.get("count"), 1)),
        min_value=1,
        max_value=200,
    )
    selector_default = coerce_str(tunnel_pool.get("selector"), "country").lower()
    tunnel_pool["selector"] = selector_default if selector_default in {"country", "region"} else "country"
    tunnel_pool["name_prefix"] = coerce_str(tunnel_pool.get("name_prefix"), "proxy")
    tunnel_pool["port_start"] = coerce_int(tunnel_pool.get("port_start"), 8111)

    existing_regions = coerce_string_list(tunnel_pool.get("regions"))
    tunnel_pool["regions"] = expand_region_list(existing_regions, tunnel_pool["count"])

    config["tunnel_pool"] = tunnel_pool
    return config

def build_tunnels_from_pool(pool: dict[str, Any], *, where: str) -> list[dict[str, Any]]:
    count = require_int(pool, "count", where=where, min_value=1, max_value=200)
    regions = optional_string_list(pool, "regions", where=where)
    if len(regions) < count:
        abort(f"{where}.regions must have at least {count} entries")
    selector = require_string(pool, "selector", where=where, default="country").lower()
    if selector not in {"country", "region"}:
        abort(f"{where}.selector must be 'country' or 'region'")
    name_prefix = require_string(pool, "name_prefix", where=where, default="proxy")
    port_start = require_int(pool, "port_start", where=where, default=8111, min_value=1, max_value=65535)
    if port_start + count - 1 > 65535:
        abort(f"{where}.port_start with count {count} exceeds max port 65535")

    tunnels: list[dict[str, Any]] = []
    for idx in range(count):
        tunnel_name = f"{name_prefix}-{idx + 1}"
        tunnel_port = port_start + idx
        location = regions[idx]
        tunnel: dict[str, Any] = {"name": tunnel_name, "port": tunnel_port}
        if selector == "country":
            tunnel["country"] = location
        else:
            tunnel["region"] = location
        tunnels.append(tunnel)
    return tunnels


def load_config(path: Path) -> ProxyConfig:
    raw = read_toml(path)
    project = require_table(raw, "project")
    defaults = require_table(raw, "defaults")
    provider = require_table(raw, "provider")
    pool = raw.get("tunnel_pool")
    raw_tunnels = raw.get("tunnels")

    tunnels: list[dict[str, Any]]
    if isinstance(pool, dict):
        tunnels = build_tunnels_from_pool(pool, where="tunnel_pool")
    elif isinstance(raw_tunnels, list) and raw_tunnels:
        tunnels = require_list_of_tables(raw, "tunnels")
    else:
        abort("config must define either [tunnel_pool] or [[tunnels]]")

    project_name = require_string(project, "name", where="project", default="vpn-proxy")
    timezone = require_string(project, "timezone", where="project", default="UTC")
    output_dir = Path(require_string(project, "output_dir", where="project", default=DEFAULT_OUTPUT_DIR))
    local_networks = optional_string_list(project, "local_networks", where="project")

    image = require_string(defaults, "image", where="defaults", default=DEFAULT_IMAGE)
    protocol = require_string(defaults, "protocol", where="defaults", default="udp")
    mssfix = require_int(defaults, "mssfix", where="defaults", default=1400, min_value=1200, max_value=2000)
    http_proxy = require_bool(defaults, "http_proxy", where="defaults", default=True)
    dot = require_bool(defaults, "dot", where="defaults", default=False)
    dns_address = optional_string(defaults, "dns_address", where="defaults")
    health_target_address = optional_string(defaults, "health_target_address", where="defaults")
    bind_address = require_string(defaults, "bind_address", where="defaults", default=DEFAULT_BIND_ADDRESS)
    enable_control_api = require_bool(defaults, "enable_control_api", where="defaults", default=False)
    control_port_start = require_int(
        defaults,
        "control_port_start",
        where="defaults",
        default=DEFAULT_CONTROL_PORT_START,
        min_value=1024,
        max_value=65535,
    )

    provider_type = require_string(provider, "type", where="provider").lower()
    if provider_type not in {"nordvpn", "gluetun"}:
        abort("provider.type must be 'nordvpn' or 'gluetun'")

    seen_names: set[str] = set()
    seen_ports: set[int] = set()
    for idx, tunnel in enumerate(tunnels):
        where = f"tunnels[{idx}]"
        tunnel_name = require_string(tunnel, "name", where=where)
        tunnel_port = require_int(tunnel, "port", where=where, min_value=1, max_value=65535)
        if tunnel_name in seen_names:
            abort(f"duplicate tunnel name '{tunnel_name}'")
        if tunnel_port in seen_ports:
            abort(f"duplicate tunnel port '{tunnel_port}'")
        seen_names.add(tunnel_name)
        seen_ports.add(tunnel_port)

    return ProxyConfig(
        project_name=project_name,
        timezone=timezone,
        output_dir=output_dir,
        image=image,
        protocol=protocol,
        mssfix=mssfix,
        http_proxy=http_proxy,
        dot=dot,
        dns_address=dns_address,
        health_target_address=health_target_address,
        bind_address=bind_address,
        local_networks=local_networks,
        enable_control_api=enable_control_api,
        control_port_start=control_port_start,
        provider=provider,
        tunnels=tunnels,
    )


def truthy_on_off(value: bool) -> str:
    return "on" if value else "off"


def normalize_service_name(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower()
    return normalized or "tunnel"


def sanitize_secret_filename(value: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._")
    if not name:
        name = "secret"
    return name.lower()


def coerce_env_value(value: Any) -> str:
    if isinstance(value, bool):
        return truthy_on_off(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    abort(f"environment values must be string/number/bool, got: {type(value).__name__}")


def table_to_env(table: dict[str, Any], *, where: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in table.items():
        if not isinstance(key, str) or not key.strip():
            abort(f"{where} contains an empty env key")
        env_key = key.strip().upper()
        result[env_key] = coerce_env_value(value)
    return result


def build_provider_environment(config: ProxyConfig) -> tuple[dict[str, str], dict[str, str]]:
    provider = config.provider
    provider_type = require_string(provider, "type", where="provider").lower()
    provider_env = table_to_env(optional_table(provider, "env", where="provider"), where="provider.env")
    secret_files: dict[str, str] = {}

    if provider_type == "nordvpn":
        username = require_string(provider, "username", where="provider")
        password = require_string(provider, "password", where="provider")
        secret_files["openvpn_user"] = username
        secret_files["openvpn_password"] = password
        provider_env.update(
            {
                "VPN_SERVICE_PROVIDER": "nordvpn",
                "OPENVPN_USER_FILE": "/gluetun/secrets/openvpn_user",
                "OPENVPN_PASSWORD_FILE": "/gluetun/secrets/openvpn_password",
            }
        )
        return provider_env, secret_files

    service = require_string(provider, "service", where="provider")
    provider_env["VPN_SERVICE_PROVIDER"] = service

    username = optional_string(provider, "username", where="provider")
    password = optional_string(provider, "password", where="provider")
    if username and not password:
        abort("provider.password is required when provider.username is set")
    if password and not username:
        abort("provider.username is required when provider.password is set")
    if username and password:
        secret_files["openvpn_user"] = username
        secret_files["openvpn_password"] = password
        provider_env["OPENVPN_USER_FILE"] = "/gluetun/secrets/openvpn_user"
        provider_env["OPENVPN_PASSWORD_FILE"] = "/gluetun/secrets/openvpn_password"

    declared_secrets = optional_table(provider, "secrets", where="provider")
    for secret_key, secret_value in declared_secrets.items():
        if not isinstance(secret_key, str) or not secret_key.strip():
            abort("provider.secrets contains an invalid key")
        if not isinstance(secret_value, (str, int, float, bool)):
            abort(f"provider.secrets.{secret_key} must be string/number/bool")
        env_key = secret_key.strip().upper()
        filename = sanitize_secret_filename(env_key)
        secret_files[filename] = coerce_env_value(secret_value)
        provider_env[f"{env_key}_FILE"] = f"/gluetun/secrets/{filename}"

    return provider_env, secret_files


def build_base_environment(config: ProxyConfig) -> dict[str, str]:
    env = {
        "OPENVPN_PROTOCOL": config.protocol,
        "OPENVPN_MSSFIX": str(config.mssfix),
        "HTTPPROXY": truthy_on_off(config.http_proxy),
        "DOT": truthy_on_off(config.dot),
        "TZ": config.timezone,
    }
    if config.local_networks:
        env["LOCAL_NETWORKS"] = ",".join(config.local_networks)
    if config.dns_address:
        env["DNS_ADDRESS"] = config.dns_address
    if config.health_target_address:
        env["HEALTH_TARGET_ADDRESS"] = config.health_target_address
    return env


def build_tunnel_environment(tunnel: dict[str, Any], *, index: int, config: ProxyConfig) -> dict[str, str]:
    where = f"tunnels[{index}]"
    env: dict[str, str] = {}
    country = optional_string(tunnel, "country", where=where)
    city = optional_string(tunnel, "city", where=where)
    region = optional_string(tunnel, "region", where=where)
    hostnames = optional_string_list(tunnel, "hostnames", where=where)
    if country:
        env["SERVER_COUNTRIES"] = country
    if city:
        env["SERVER_CITIES"] = city
    if region:
        env["SERVER_REGIONS"] = region
    if hostnames:
        env["SERVER_HOSTNAMES"] = ",".join(hostnames)
    env.update(table_to_env(optional_table(tunnel, "extra_env", where=where), where=f"{where}.extra_env"))
    return env


def format_yaml_scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    abort(f"unsupported YAML scalar type: {type(value).__name__}")


def dump_yaml(value: Any, *, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines: list[str] = []

    if isinstance(value, dict):
        if not value:
            return [f"{pad}{{}}"]
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                if not child:
                    empty = "{}" if isinstance(child, dict) else "[]"
                    lines.append(f"{pad}{key}: {empty}")
                else:
                    lines.append(f"{pad}{key}:")
                    lines.extend(dump_yaml(child, indent=indent + 2))
            else:
                lines.append(f"{pad}{key}: {format_yaml_scalar(child)}")
        return lines

    if isinstance(value, list):
        if not value:
            return [f"{pad}[]"]
        for child in value:
            if isinstance(child, (dict, list)):
                if not child:
                    lines.append(f"{pad}- {{}}")
                    continue
                lines.append(f"{pad}-")
                lines.extend(dump_yaml(child, indent=indent + 2))
            else:
                lines.append(f"{pad}- {format_yaml_scalar(child)}")
        return lines

    return [f"{pad}{format_yaml_scalar(value)}"]


def write_secure_file(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except PermissionError:
        # Windows and some shared filesystems may reject chmod.
        pass


def generate_compose(config_path: Path) -> GenerationResult:
    config = load_config(config_path)
    provider_env, secret_files = build_provider_environment(config)
    base_env = build_base_environment(config)

    output_dir = (config_path.parent / config.output_dir).resolve()
    secrets_dir = output_dir / SECRETS_DIR_NAME
    compose_path = output_dir / "compose.yml"
    output_dir.mkdir(parents=True, exist_ok=True)
    secrets_dir.mkdir(parents=True, exist_ok=True)

    for filename, secret_value in secret_files.items():
        write_secure_file(secrets_dir / filename, secret_value)

    compose: dict[str, Any] = {"name": config.project_name, "services": {}}

    endpoints: list[tuple[str, str]] = []
    for idx, tunnel in enumerate(config.tunnels):
        tunnel_name = require_string(tunnel, "name", where=f"tunnels[{idx}]")
        service_name = normalize_service_name(tunnel_name)
        tunnel_port = require_int(tunnel, "port", where=f"tunnels[{idx}]", min_value=1, max_value=65535)

        env: dict[str, str] = {}
        env.update(base_env)
        env.update(provider_env)
        env.update(build_tunnel_environment(tunnel, index=idx, config=config))

        ports = [f"{config.bind_address}:{tunnel_port}:8888"]
        if config.enable_control_api:
            ports.append(f"{config.bind_address}:{config.control_port_start + idx}:8000")

        service = {
            "image": config.image,
            "cap_add": ["NET_ADMIN"],
            "devices": ["/dev/net/tun"],
            "restart": "unless-stopped",
            "environment": env,
            "volumes": [f"./{SECRETS_DIR_NAME}:/gluetun/secrets:ro"],
            "ports": ports,
        }
        compose["services"][service_name] = service
        endpoints.append((tunnel_name, f"http://{config.bind_address}:{tunnel_port}"))

    yaml_content = "\n".join(dump_yaml(compose)) + "\n"
    compose_path.write_text(yaml_content, encoding="utf-8")
    return GenerationResult(compose_path=compose_path, endpoints=endpoints, output_dir=output_dir)


def require_docker() -> None:
    if shutil.which("docker") is None:
        abort("docker is not installed or not in PATH")


def run_docker_compose(compose_path: Path, args: list[str]) -> int:
    require_docker()
    command = ["docker", "compose", "-f", str(compose_path)] + args
    process = subprocess.run(command, check=False)
    return process.returncode


def run_command_capture(command: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(command, check=False, capture_output=True, text=True)
    return process.returncode, process.stdout, process.stderr


def get_compose_container_ids(compose_path: Path) -> list[str]:
    code, stdout, stderr = run_command_capture(["docker", "compose", "-f", str(compose_path), "ps", "-q"])
    if code != 0:
        abort(f"failed to list compose containers: {stderr.strip() or stdout.strip()}")
    ids = [line.strip() for line in stdout.splitlines() if line.strip()]
    return ids


def get_container_name(container_id: str) -> str:
    code, stdout, _ = run_command_capture(["docker", "inspect", "-f", "{{.Name}}", container_id])
    if code != 0:
        return container_id
    return stdout.strip().lstrip("/") or container_id


def get_container_health(container_id: str) -> str:
    code, stdout, _ = run_command_capture(["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container_id])
    if code != 0:
        return "unknown"
    return stdout.strip() or "unknown"


def wait_for_compose_healthy(compose_path: Path, timeout_seconds: int) -> tuple[bool, dict[str, str]]:
    deadline = time.time() + timeout_seconds
    last_status: dict[str, str] = {}

    while True:
        container_ids = get_compose_container_ids(compose_path)
        if not container_ids:
            return False, {}

        statuses: dict[str, str] = {}
        all_healthy = True
        for container_id in container_ids:
            name = get_container_name(container_id)
            health = get_container_health(container_id)
            statuses[name] = health
            # Containers without healthcheck are treated as healthy-enough.
            if health not in {"healthy", "none"}:
                all_healthy = False
        last_status = statuses
        if all_healthy:
            return True, statuses
        if time.time() >= deadline:
            return False, statuses
        time.sleep(2)


def print_compose_failure_logs(compose_path: Path, statuses: dict[str, str]) -> None:
    failing = [name for name, status in statuses.items() if status not in {"healthy", "none"}]
    if not failing:
        return
    for name in failing:
        print(f"\n--- logs: {name} ---", file=sys.stderr)
        subprocess.run(["docker", "logs", "--tail", "60", name], check=False)


def unhealthy_container_names(statuses: dict[str, str]) -> list[str]:
    return sorted(name for name, status in statuses.items() if status not in {"healthy", "none"})


def restart_containers(container_names: list[str]) -> bool:
    if not container_names:
        return True
    print(f"restarting unhealthy container(s): {', '.join(container_names)}")
    for name in container_names:
        process = subprocess.run(["docker", "restart", name], check=False)
        if process.returncode != 0:
            print(f"error: failed to restart container {name}", file=sys.stderr)
            return False
    return True


def cmd_init(args: argparse.Namespace) -> int:
    destination = Path(args.config).resolve()
    existed_before = destination.exists()
    if destination.exists() and not args.force and args.template:
        abort(f"{destination} already exists (use --force to overwrite)")

    destination.parent.mkdir(parents=True, exist_ok=True)

    if args.template:
        template = render_config_toml(default_config_template(provider_type=args.provider))
        destination.write_text(template, encoding="utf-8")
        print(f"created template {destination}")
        print("next: edit credentials, then run `./proxyctl up`")
        return 0

    if args.force or not existed_before:
        seed = default_config_template(provider_type=args.provider)
    else:
        seed = load_wizard_seed(destination, provider_type=args.provider)

    config = run_config_wizard(seed, mode="init")
    destination.write_text(render_config_toml(config), encoding="utf-8")
    action = "updated" if existed_before and not args.force else "created"
    print(f"{action} config: {destination}")
    print("change countries/regions in [tunnel_pool].regions, e.g. regions = [\"Finland\", \"Netherlands\", \"Switzerland\"]")
    print("next: run `./proxyctl up`")
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    destination = Path(args.config).resolve()
    if not destination.exists():
        abort(f"missing config file: {destination} (run `./proxyctl init` first)")
    print(f"config file: {destination}")
    print("edit this file directly, then run `./proxyctl up`")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    result = generate_compose(Path(args.config).resolve())
    print(f"generated {result.compose_path}")
    for name, url in result.endpoints:
        print(f"- {name}: {url}")
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    result = generate_compose(config_path)
    code = run_docker_compose(result.compose_path, ["up", "-d"])
    if code != 0:
        return code

    if args.restart_retries < 0:
        abort("--restart-retries must be >= 0")
    if args.restart_backoff < 0:
        abort("--restart-backoff must be >= 0")

    if args.wait:
        total_attempts = args.restart_retries + 1
        statuses: dict[str, str] = {}
        ok = False
        for attempt in range(1, total_attempts + 1):
            ok, statuses = wait_for_compose_healthy(result.compose_path, timeout_seconds=args.wait_timeout)
            if ok:
                break
            failing = unhealthy_container_names(statuses)
            print(
                f"startup health attempt {attempt}/{total_attempts} failed ({len(failing)} unhealthy container(s))",
                file=sys.stderr,
            )
            for name in failing:
                print(f"- {name}: {statuses[name]}", file=sys.stderr)
            if attempt == total_attempts:
                break
            if not restart_containers(failing):
                print_compose_failure_logs(result.compose_path, statuses)
                return 1
            if args.restart_backoff > 0:
                print(
                    f"waiting {args.restart_backoff:.1f}s before next health attempt",
                    file=sys.stderr,
                )
                time.sleep(args.restart_backoff)

        if not ok:
            print("error: proxy stack started but did not become healthy in time", file=sys.stderr)
            for name, status in sorted(statuses.items()):
                print(f"- {name}: {status}", file=sys.stderr)
            print_compose_failure_logs(result.compose_path, statuses)
            return 1
        print("proxy stack is up")
    else:
        print("proxy stack started in background (detached)")
        print("use `./proxyctl status` to check health")

    for name, url in result.endpoints:
        print(f"- {name}: {url}")
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    compose_path = (config_path.parent / config.output_dir).resolve() / "compose.yml"
    if not compose_path.exists():
        abort(f"missing generated compose file: {compose_path} (run generate or up first)")
    down_args = ["down"]
    if args.remove_volumes:
        down_args.append("--volumes")
    return run_docker_compose(compose_path, down_args)


def cmd_status(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    compose_path = (config_path.parent / config.output_dir).resolve() / "compose.yml"
    if not compose_path.exists():
        abort(f"missing generated compose file: {compose_path} (run generate or up first)")
    return run_docker_compose(compose_path, ["ps"])


def cmd_endpoints(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config).resolve())
    for idx, tunnel in enumerate(config.tunnels):
        tunnel_name = require_string(tunnel, "name", where=f"tunnels[{idx}]")
        tunnel_port = require_int(tunnel, "port", where=f"tunnels[{idx}]", min_value=1, max_value=65535)
        print(f"{tunnel_name}: http://{config.bind_address}:{tunnel_port}")
    return 0


def print_doctor_item(name: str, ok: bool, detail: str) -> None:
    state = "ok" if ok else "fail"
    print(f"[{state}] {name}: {detail}")


def cmd_doctor(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    failures = 0

    exists = config_path.exists()
    if exists:
        print_doctor_item("config file", True, str(config_path))
    else:
        print_doctor_item("config file", False, f"missing ({config_path})")
        failures += 1

    if exists:
        buffer = io.StringIO()
        parsed_config: ProxyConfig | None = None
        try:
            with contextlib.redirect_stderr(buffer):
                parsed_config = load_config(config_path)
        except SystemExit:
            message = buffer.getvalue().strip() or "invalid config"
            print_doctor_item("config validation", False, message)
            failures += 1
        else:
            print_doctor_item("config validation", True, f"{len(parsed_config.tunnels)} tunnel(s) configured")

    docker_binary = shutil.which("docker")
    if docker_binary:
        print_doctor_item("docker binary", True, docker_binary)
    else:
        print_doctor_item("docker binary", False, "docker not found in PATH")
        failures += 1

    if docker_binary:
        code, stdout, stderr = run_command_capture(["docker", "compose", "version", "--short"])
        if code == 0:
            version = stdout.strip() or "available"
            print_doctor_item("docker compose", True, version)
        else:
            detail = stderr.strip() or stdout.strip() or "compose plugin unavailable"
            print_doctor_item("docker compose", False, detail)
            failures += 1

        code, stdout, stderr = run_command_capture(["docker", "info", "--format", "{{.ServerVersion}}"])
        if code == 0:
            server_version = stdout.strip() or "reachable"
            print_doctor_item("docker daemon", True, f"server {server_version}")
        else:
            detail = stderr.strip() or stdout.strip() or "daemon unreachable"
            print_doctor_item("docker daemon", False, detail)
            failures += 1

    if failures:
        print(f"doctor failed: {failures} issue(s) found", file=sys.stderr)
        return 1
    print("doctor passed: environment looks ready")
    return 0


def probe_proxy(proxy_url: str, test_url: str, timeout_seconds: float) -> tuple[bool, str]:
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(test_url, headers={"User-Agent": "vpn-proxy-check/1.0"})
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            body = response.read(128).decode("utf-8", errors="replace").strip().replace("\n", " ")
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                return False, f"HTTP {status}"
            return True, body or "reachable"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, str(exc.reason)
    except TimeoutError:
        return False, "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def cmd_check(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config).resolve())
    failed = 0
    for idx, tunnel in enumerate(config.tunnels):
        name = require_string(tunnel, "name", where=f"tunnels[{idx}]")
        port = require_int(tunnel, "port", where=f"tunnels[{idx}]", min_value=1, max_value=65535)
        proxy_url = f"http://{config.bind_address}:{port}"
        ok, detail = probe_proxy(proxy_url, args.url, timeout_seconds=args.timeout)
        status = "OK" if ok else "FAIL"
        print(f"{status} {name} {proxy_url} -> {detail}")
        if not ok:
            failed += 1
    if failed:
        print(f"proxy check failed: {failed}/{len(config.tunnels)} endpoint(s)", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxyctl",
        description="Generate and operate a self-hosted VPN proxy stack.",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"path to proxy config (default: {DEFAULT_CONFIG_FILE})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="run interactive setup wizard")
    init_parser.add_argument(
        "--provider",
        choices=["nordvpn", "gluetun"],
        default="nordvpn",
        help="preferred provider mode in the wizard",
    )
    init_parser.add_argument(
        "--template",
        action="store_true",
        help="write a non-interactive starter template instead of launching wizard",
    )
    init_parser.add_argument("--force", action="store_true", help="overwrite existing config file")
    init_parser.set_defaults(func=cmd_init)

    edit_parser = subparsers.add_parser("edit", help="print config file path for manual editing")
    edit_parser.set_defaults(func=cmd_edit)

    generate_parser = subparsers.add_parser("generate", help="generate compose + secret files")
    generate_parser.set_defaults(func=cmd_generate)

    up_parser = subparsers.add_parser("up", help="generate and start the proxy stack")
    up_parser.add_argument(
        "--wait",
        action="store_true",
        help="wait for container healthchecks and fail if unhealthy",
    )
    up_parser.add_argument(
        "--wait-timeout",
        type=int,
        default=90,
        help="seconds to wait for healthy containers (default: 90)",
    )
    up_parser.add_argument(
        "--restart-retries",
        type=int,
        default=2,
        help="restart unhealthy containers this many times while waiting (default: 2)",
    )
    up_parser.add_argument(
        "--restart-backoff",
        type=float,
        default=3.0,
        help="seconds to wait after each unhealthy restart cycle (default: 3)",
    )
    up_parser.set_defaults(wait=False)
    up_parser.set_defaults(func=cmd_up)

    down_parser = subparsers.add_parser("down", help="stop the proxy stack")
    down_parser.add_argument("--remove-volumes", action="store_true", help="remove volumes when stopping")
    down_parser.set_defaults(func=cmd_down)

    status_parser = subparsers.add_parser("status", help="show docker compose status")
    status_parser.set_defaults(func=cmd_status)

    endpoints_parser = subparsers.add_parser("endpoints", help="print configured proxy endpoints")
    endpoints_parser.set_defaults(func=cmd_endpoints)

    doctor_parser = subparsers.add_parser("doctor", help="check local prerequisites and config validity")
    doctor_parser.set_defaults(func=cmd_doctor)

    check_parser = subparsers.add_parser("check", help="test all configured proxy endpoints")
    check_parser.add_argument(
        "--url",
        default="https://api.ipify.org",
        help="test URL fetched through each proxy (default: https://api.ipify.org)",
    )
    check_parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="request timeout in seconds (default: 20)",
    )
    check_parser.set_defaults(func=cmd_check)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
