#!/usr/bin/env python3
"""Convert a Clash subscription into a Surge configuration file.

Example:

    python clash_to_surge.py "https://example.com/subscription?target=clash" -o surge.conf

The script automatically detects plain YAML, Base64, and gzip-encoded
subscriptions and produces a Surge-compatible configuration. Warnings are
reported for items that cannot be mapped precisely.

PyYAML is required: install it with ``pip install pyyaml``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ModuleNotFoundError as exc:  # pragma: no cover - explicit dependency hint
    print(
        "PyYAML is required. Please install it first: `pip install pyyaml`.",
        file=sys.stderr,
    )
    raise


@dataclass
class ConvertResult:
    surge_config: str
    warnings: List[str]


def fetch_subscription(source: str, timeout: int = 20) -> bytes:
    """Load a Clash subscription from either a URL or a local file."""

    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        req = urllib.request.Request(
            source,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                encoding = resp.headers.get("Content-Encoding", "").lower()
        except urllib.error.URLError as err:
            raise RuntimeError(f"Failed to fetch subscription: {err}") from err

        if encoding == "gzip":
            return gzip.decompress(data)
        if encoding == "br":
            try:
                import brotli  # type: ignore
            except ModuleNotFoundError as err:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "The subscription is Brotli-compressed. Install brotli first: `pip install brotli`."
                ) from err
            return brotli.decompress(data)
        if data.startswith(b"\x1f\x8b"):
            return gzip.decompress(data)
        return data

    if os.path.isfile(source):
        with open(source, "rb") as fp:
            return fp.read()

    raise RuntimeError("Invalid source: please pass a valid URL or an existing file path.")


def decode_subscription_payload(raw: bytes) -> str:
    """Try to turn raw subscription bytes into a YAML string."""

    for encoding in ("utf-8", "utf-8-sig", "gb18030"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "proxies:" in text or "proxy-groups:" in text or "proxy_providers" in text:
            return text

    # some providers return Base64-encoded data
    compact = raw.strip()
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        decoded = None

    if not decoded:
        # loosen validation: allow whitespace or missing padding
        try:
            decoded = base64.b64decode(compact + b"==")
        except Exception as err:
            raise RuntimeError("Unable to recognise subscription format. Make sure it is a Clash subscription.") from err

    if decoded.startswith(b"\x1f\x8b"):
        decoded = gzip.decompress(decoded)

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as err:
        raise RuntimeError("Subscription content is not valid UTF-8 text.") from err


def load_clash_config(source: str, timeout: int = 20) -> dict:
    raw = fetch_subscription(source, timeout=timeout)
    text = decode_subscription_payload(raw)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise RuntimeError(f"Failed to parse YAML: {err}") from err
    if not isinstance(data, dict):
        raise RuntimeError("Subscription content is not a valid Clash configuration.")
    return data


def convert_proxies(proxies: Iterable[dict]) -> Tuple[List[str], List[str]]:
    lines: List[str] = []
    warnings: List[str] = []
    for proxy in proxies or []:
        name = proxy.get("name")
        if not name:
            warnings.append("A proxy without a name was skipped.")
            continue
        proxy_type = (proxy.get("type") or "").lower()
        converter = PROXY_CONVERTERS.get(proxy_type)
        if not converter:
            warnings.append(f"Proxy {name} uses unsupported type {proxy_type}; skipped.")
            continue
        try:
            surge_body, extra_warnings = converter(proxy)
        except Exception as err:  # pragma: no cover - safety net
            warnings.append(f"Proxy {name} failed to convert: {err}")
            continue
        if surge_body:
            lines.append(f"{name} = {surge_body}")
        warnings.extend(extra_warnings)
    return lines, warnings


def convert_proxy_groups(groups: Iterable[dict]) -> Tuple[List[str], List[str]]:
    lines: List[str] = []
    warnings: List[str] = []
    type_map = {
        "select": "select",
        "url-test": "url-test",
        "fallback": "fallback",
        "load-balance": "load-balance",
    }
    for group in groups or []:
        name = group.get("name")
        if not name:
            warnings.append("A proxy group without a name was skipped.")
            continue
        group_type = (group.get("type") or "").lower()
        surge_type = type_map.get(group_type)
        if not surge_type:
            warnings.append(f"Proxy group {name} uses unsupported type {group_type}; treated as select.")
            surge_type = "select"
        entries = group.get("proxies") or []
        uses = group.get("use") or []
        if uses:
            warnings.append(
                f"Proxy group {name} references proxy-providers ({', '.join(uses)}); please add them manually."
            )
        params: List[str] = [surge_type]
        params.extend(entries)
        if group_type in {"url-test", "fallback", "load-balance"}:
            url = group.get("url", "http://www.gstatic.com/generate_204")
            interval = group.get("interval", 600)
            params.append(f"url={url}")
            params.append(f"interval={interval}")
            tolerance = group.get("tolerance")
            if tolerance is not None:
                params.append(f"tolerance={tolerance}")
        if group_type == "load-balance":
            strategy = group.get("strategy")
            if strategy:
                params.append(f"strategy={strategy}")
        lines.append(f"{name} = {', '.join(params)}")
    return lines, warnings


def convert_rules(
    rules: Iterable[str],
    rule_providers: Optional[Dict[str, dict]] = None,
) -> Tuple[List[str], List[str]]:
    result: List[str] = []
    warnings: List[str] = []
    providers = rule_providers or {}

    for rule in rules or []:
        if isinstance(rule, str):
            parts = [part.strip() for part in rule.split(",")]
        elif isinstance(rule, (list, tuple)):
            parts = [str(part).strip() for part in rule]
        else:
            warnings.append(f"Unrecognised rule format: {rule}")
            continue
        if not parts:
            continue

        keyword = parts[0].upper()
        if keyword == "MATCH":
            if len(parts) < 2:
                warnings.append("MATCH rule without a policy was ignored.")
                continue
            result.append(f"FINAL,{parts[1]}")
            continue
        if keyword == "RULE-SET":
            if len(parts) < 3:
                warnings.append(f"RULE-SET rule is missing arguments: {rule}")
                continue
            provider_name = parts[1]
            policy = parts[2]
            provider = providers.get(provider_name)
            if not provider:
                warnings.append(
                    f"rule-provider {provider_name} not found in subscription; original rule was kept."
                )
                result.append(",".join(parts))
                continue
            url = provider.get("url")
            if not url:
                warnings.append(
                    f"rule-provider {provider_name} does not include url; original rule was kept."
                )
                result.append(",".join(parts))
                continue
            interval = provider.get("interval") or provider.get("update-interval")
            behavior = provider.get("behavior")
            extras: List[str] = []
            if interval:
                extras.append(f"update-interval={interval}")
            if behavior and behavior.lower() != "classical":
                extras.append(f"behavior={behavior}")
            composed = ["RULE-SET", provider_name, url, policy]
            composed.extend(extras)
            result.append(",".join(str(item) for item in composed))
            continue

        result.append(",".join(parts))

    return result, warnings


def generate_general_section(custom_items: Optional[List[str]] = None) -> str:
    base = {
        "loglevel": "notify",
        "ipv6": "true",
        "skip-proxy": "127.0.0.1, 0.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1",
        "udp-policy-not-supported-behaviour": "reject",
    }

    items = list(base.items())
    if custom_items:
        for item in custom_items:
            if "=" not in item:
                raise ValueError(f"[General] custom item must be in key=value format: {item}")
            key, value = item.split("=", 1)
            items.append((key.strip(), value.strip()))

    return "\n".join(f"{key} = {value}" for key, value in items)


def convert_clash_to_surge(config: dict, general_overrides: Optional[List[str]] = None) -> ConvertResult:
    warnings: List[str] = []

    proxies_section = config.get("proxies") or []
    proxy_lines, proxy_warnings = convert_proxies(proxies_section)
    warnings.extend(proxy_warnings)

    group_lines: List[str] = []
    group_warnings: List[str] = []
    if "proxy-groups" in config:
        group_lines, group_warnings = convert_proxy_groups(config.get("proxy-groups") or [])
    elif "proxy_groups" in config:
        group_lines, group_warnings = convert_proxy_groups(config.get("proxy_groups") or [])
    warnings.extend(group_warnings)

    rules_section = config.get("rules") or []
    providers = config.get("rule-providers") or config.get("rule_providers")
    rule_lines, rule_warnings = convert_rules(rules_section, providers)
    warnings.extend(rule_warnings)

    general_content = generate_general_section(general_overrides)

    sections = [
        "; Generated by clash_to_surge.py",
        "[General]",
        general_content,
        "",
        "[Proxy]",
    ]
    if proxy_lines:
        sections.extend(proxy_lines)
    else:
        sections.append("; No usable proxies were found in the subscription.")

    sections.extend(["", "[Proxy Group]"])
    if group_lines:
        sections.extend(group_lines)
    else:
        sections.append("; No usable proxy groups were found in the subscription.")

    sections.extend(["", "[Rule]"])
    if rule_lines:
        sections.extend(rule_lines)
    else:
        sections.append("FINAL,DIRECT")

    surge_config = "\n".join(sections).strip() + "\n"
    return ConvertResult(surge_config=surge_config, warnings=warnings)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert a Clash subscription into a Surge profile.")
    parser.add_argument("source", help="Clash subscription URL or YAML file path")
    parser.add_argument("-o", "--output", help="Path to write the generated Surge profile")
    parser.add_argument(
        "--timeout", type=int, default=20, help="Timeout in seconds for downloading the subscription (default: 20)"
    )
    parser.add_argument(
        "--general",
        action="append",
        dest="general_items",
        help="Extra [General] entries in key=value form; can be repeated",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        clash_config = load_clash_config(args.source, timeout=args.timeout)
        result = convert_clash_to_surge(
            clash_config, general_overrides=args.general_items
        )
    except Exception as err:
        print(f"Conversion failed: {err}", file=sys.stderr)
        return 1

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fp:
                fp.write(result.surge_config)
        except OSError as err:
            print(f"Failed to write output file: {err}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(result.surge_config)

    if result.warnings:
        print("\nConversion finished with warnings:", file=sys.stderr)
        for item in result.warnings:
            print(f" - {item}", file=sys.stderr)
    else:
        print("Conversion finished successfully.", file=sys.stderr)

    return 0


# --- Proxy conversion helpers ---


def _quote_header(headers: Dict[str, str]) -> str:
    return "|".join(f"{k}:{v}" for k, v in headers.items())


def _convert_shadowrocket_plugin(proxy: dict, params: List[str], warnings: List[str]) -> None:
    plugin = proxy.get("plugin")
    if not plugin:
        return
    plugin_opts = proxy.get("plugin-opts") or proxy.get("plugin_opts") or {}
    if plugin == "obfs":
        mode = plugin_opts.get("mode")
        host = plugin_opts.get("host")
        if mode:
            params.append(f"obfs={mode}")
        if host:
            params.append(f"obfs-host={host}")
        uri = plugin_opts.get("uri")
        if uri:
            params.append(f"obfs-uri={uri}")
        return
    if plugin == "v2ray-plugin":
        tls = plugin_opts.get("tls")
        mode = plugin_opts.get("mode")
        host = plugin_opts.get("host") or plugin_opts.get("headers", {}).get("Host")
        path = plugin_opts.get("path")
        params.append("ws=true")
        if tls:
            params.append("tls=true")
        if host:
            params.append(f"ws-headers=Host:{host}")
        if path:
            params.append(f"ws-path={path}")
        if mode:
            params.append(f"mode={mode}")
        return

    warnings.append(f"Shadowsocks plugin {plugin} is not supported; related options were ignored.")


def convert_ss(proxy: dict) -> Tuple[str, List[str]]:
    warnings: List[str] = []
    server = proxy.get("server")
    port = proxy.get("port")
    cipher = proxy.get("cipher")
    password = proxy.get("password")
    if not all([server, port, cipher, password]):
        raise ValueError("Shadowsocks proxy is missing server/port/cipher/password.")
    params: List[str] = ["ss", str(server), str(port), f"encrypt-method={cipher}", f"password={password}"]
    if proxy.get("udp"):
        params.append("udp-relay=true")
    _convert_shadowrocket_plugin(proxy, params, warnings)
    return ", ".join(params), warnings


def convert_vmess(proxy: dict) -> Tuple[str, List[str]]:
    warnings: List[str] = []
    server = proxy.get("server")
    port = proxy.get("port")
    uuid = proxy.get("uuid") or proxy.get("password")
    if not all([server, port, uuid]):
        raise ValueError("VMess ???? server/port/uuid ??")
    cipher = proxy.get("cipher")
    network = (proxy.get("network") or "tcp").lower()
    tls_enabled = proxy.get("tls") or proxy.get("tls") == "true"
    params: List[str] = ["vmess", str(server), str(port), f"username={uuid}"]
    if cipher and cipher != "auto":
        params.append(f"encrypt-method={cipher}")
    alter_id = proxy.get("alterId") or proxy.get("alterId", 0)
    if alter_id:
        params.append(f"alterId={alter_id}")
    if tls_enabled:
        params.append("tls=true")
        if proxy.get("skip-cert-verify"):
            params.append("skip-cert-verify=true")
        sni = proxy.get("servername") or proxy.get("sni")
        if sni:
            params.append(f"sni={sni}")
    if network == "ws":
        params.append("ws=true")
        ws_opts = proxy.get("ws-opts") or proxy.get("ws_opts") or {}
        path = ws_opts.get("path") or "/"
        params.append(f"ws-path={path}")
        headers = ws_opts.get("headers") or {}
        if headers:
            params.append(f"ws-headers={_quote_header(headers)}")
    elif network == "http":
        params.append("http=true")
        http_opts = proxy.get("http-opts") or proxy.get("http_opts") or {}
        method = http_opts.get("method")
        if method:
            params.append(f"method={method}")
    elif network not in {"tcp"}:
        warnings.append(f"VMess proxy {proxy.get('name')} uses unsupported network={network}.")
    return ", ".join(params), warnings


def convert_trojan(proxy: dict) -> Tuple[str, List[str]]:
    warnings: List[str] = []
    server = proxy.get("server")
    port = proxy.get("port")
    password = proxy.get("password")
    if not all([server, port, password]):
        raise ValueError("Trojan proxy is missing server/port/password.")
    params: List[str] = ["trojan", str(server), str(port), f"password={password}"]
    sni = proxy.get("sni") or proxy.get("servername")
    if sni:
        params.append(f"sni={sni}")
    if proxy.get("skip-cert-verify"):
        params.append("skip-cert-verify=true")
    alpn = proxy.get("alpn")
    if isinstance(alpn, list) and alpn:
        params.append("alpn=" + ":".join(alpn))
    return ", ".join(params), warnings


def convert_http(proxy: dict) -> Tuple[str, List[str]]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not all([server, port]):
        raise ValueError("HTTP proxy is missing server/port.")
    params: List[str] = ["http", str(server), str(port)]
    if proxy.get("username"):
        params.append(f"username={proxy['username']}")
    if proxy.get("password"):
        params.append(f"password={proxy['password']}")
    if proxy.get("tls"):
        params.append("tls=true")
    return ", ".join(params), []


def convert_socks5(proxy: dict) -> Tuple[str, List[str]]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not all([server, port]):
        raise ValueError("Socks5 proxy is missing server/port.")
    params: List[str] = ["socks5", str(server), str(port)]
    if proxy.get("username"):
        params.append(f"username={proxy['username']}")
    if proxy.get("password"):
        params.append(f"password={proxy['password']}")
    return ", ".join(params), []


PROXY_CONVERTERS = {
    "ss": convert_ss,
    "shadowsocks": convert_ss,
    "vmess": convert_vmess,
    "trojan": convert_trojan,
    "http": convert_http,
    "https": convert_http,
    "socks5": convert_socks5,
}


if __name__ == "__main__":  # pragma: no cover - script entry
    sys.exit(main())
