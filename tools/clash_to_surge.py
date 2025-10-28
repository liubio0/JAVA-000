#!/usr/bin/env python3
import sys
import os
import yaml
import base64
import re
from urllib.parse import urlparse, parse_qs, quote

# Minimal converter: Clash YAML -> Surge conf
# Handles: proxies (vmess, trojan, ss, ssr, http/socks), proxy-groups (url-test/fallback/select), rules
# Outputs: [General], [Proxy], [Proxy Group], [Rule]

# Helpers

def b64decode_auto(s: str) -> str:
    s = s.strip()
    # add padding if needed
    missing = len(s) % 4
    if missing:
        s += '=' * (4 - missing)
    try:
        return base64.urlsafe_b64decode(s.encode()).decode('utf-8', 'ignore')
    except Exception:
        try:
            return base64.b64decode(s.encode()).decode('utf-8', 'ignore')
        except Exception:
            return s

def read_yaml(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def to_surge_proxy(entry: dict) -> str:
    """Convert one Clash proxy entry to Surge line."""
    name = entry.get('name') or 'noname'
    typ = (entry.get('type') or '').lower()

    # normalize common fields
    server = entry.get('server') or entry.get('server_name') or ''
    port = entry.get('port') or entry.get('server_port') or 0

    if typ == 'ss':
        cipher = entry.get('cipher') or entry.get('method') or ''
        password = entry.get('password') or ''
        plugin = entry.get('plugin')
        plugin_opts = entry.get('plugin-opts') or {}
        parts = [name, ' = ', 'shadowsocks', ', ', f"{server}", ', ', str(port), ', ', f"encrypt-method={cipher}", ', ', f"password={password}"]
        # plugin (obfs) -> obfs, obfs-host
        if plugin and 'obfs' in plugin.lower():
            obfs = plugin_opts.get('mode') or plugin_opts.get('obfs')
            obfs_host = plugin_opts.get('host') or plugin_opts.get('obfs-host')
            if obfs:
                parts += [', ', f"obfs={obfs}"]
            if obfs_host:
                parts += [', ', f"obfs-host={obfs_host}"]
        # udp relay
        if entry.get('udp'):
            parts += [', ', 'udp-relay=true']
        return ''.join(parts)

    if typ == 'ssr':
        cipher = entry.get('cipher') or entry.get('method') or ''
        password = entry.get('password') or ''
        protocol = entry.get('protocol') or ''
        obfs = entry.get('obfs') or ''
        obfsparam = entry.get('obfs-param') or entry.get('obfs-param') or ''
        protoparam = entry.get('protocol-param') or ''
        parts = [name, ' = ', 'shadowsocksr', ', ', f"{server}", ', ', str(port), ', ', f"encrypt-method={cipher}", ', ', f"password={password}"]
        if protocol:
            parts += [', ', f"protocol={protocol}"]
        if protoparam:
            parts += [', ', f"protocol-param={protoparam}"]
        if obfs:
            parts += [', ', f"obfs={obfs}"]
        if obfsparam:
            parts += [', ', f"obfs-param={obfsparam}"]
        if entry.get('udp'):
            parts += [', ', 'udp-relay=true']
        return ''.join(parts)

    if typ == 'vmess':
        uuid = entry.get('uuid') or entry.get('id') or ''
        cipher = entry.get('cipher') or 'auto'
        tls = entry.get('tls') or False
        sni = entry.get('servername') or entry.get('server_name') or entry.get('sni') or ''
        network = (entry.get('network') or '').lower()  # ws, grpc, http
        ws_opts = entry.get('ws-opts') or {}
        ws_headers = ws_opts.get('headers') or {}
        host = ws_headers.get('Host') or ws_headers.get('host') or ''
        path = ws_opts.get('path') or ''
        grpc_opts = entry.get('grpc-opts') or {}
        grpc_service = grpc_opts.get('grpc-service-name') or grpc_opts.get('grpc-service-name') or ''

        parts = [name, ' = ', 'vmess', ', ', f"{server}", ', ', str(port), ', ', f"username={uuid}"]
        if cipher and cipher != 'auto':
            parts += [', ', f"encrypt-method={cipher}"]
        if tls:
            parts += [', ', 'tls=true']
        if sni:
            parts += [', ', f"sni={sni}"]
        if network == 'ws':
            parts += [', ', 'ws=true']
            if host:
                parts += [', ', f"ws-headers=Host:{host}"]
            if path:
                parts += [', ', f"ws-path={path}"]
        if network == 'grpc':
            parts += [', ', 'grpc=true']
            if grpc_service:
                parts += [', ', f"grpc-service-name={grpc_service}"]
        if entry.get('udp'):
            parts += [', ', 'udp-relay=true']
        return ''.join(parts)

    if typ == 'trojan':
        password = entry.get('password') or ''
        sni = entry.get('sni') or entry.get('servername') or ''
        alpn = entry.get('alpn') or []
        skip_cert_verify = entry.get('skip-cert-verify')
        parts = [name, ' = ', 'trojan', ', ', f"{server}", ', ', str(port), ', ', f"password={password}"]
        if sni:
            parts += [', ', f"sni={sni}"]
        if alpn:
            parts += [', ', f"alpn={'|'.join(alpn)}"]
        if skip_cert_verify is True:
            parts += [', ', 'skip-cert-verify=true']
        return ''.join(parts)

    if typ in ('http', 'https'):
        username = entry.get('username') or ''
        password = entry.get('password') or ''
        tls = (typ == 'https') or entry.get('tls')
        parts = [name, ' = ', 'http', ', ', f"{server}", ', ', str(port)]
        if username:
            parts += [', ', f"username={username}"]
        if password:
            parts += [', ', f"password={password}"]
        if tls:
            parts += [', ', 'tls=true']
        return ''.join(parts)

    if typ in ('socks', 'socks5'):
        username = entry.get('username') or ''
        password = entry.get('password') or ''
        parts = [name, ' = ', 'socks5', ', ', f"{server}", ', ', str(port)]
        if username:
            parts += [', ', f"username={username}"]
        if password:
            parts += [', ', f"password={password}"]
        return ''.join(parts)

    # fallback: treat as http
    return f"{name} = http, {server}, {port}"


def to_surge_group(group: dict, proxy_names: list[str]) -> str:
    name = group.get('name') or 'GROUP'
    typ = (group.get('type') or '').lower()
    proxies = group.get('proxies') or []
    url = group.get('url') or 'http://www.gstatic.com/generate_204'
    interval = group.get('interval') or 300

    # only keep proxies that exist
    proxies = [p for p in proxies if p in proxy_names or p in ("DIRECT", "REJECT")]
    base = f"{name} = select, {', '.join(proxies)}" if typ == 'select' else None

    if typ in ('url-test', 'fallback', 'load-balance'):
        mode = {
            'url-test': 'url-test',
            'fallback': 'fallback',
            'load-balance': 'load-balance'
        }[typ]
        if not proxies:
            proxies = ['DIRECT']
        result = f"{name} = {mode}, {', '.join(proxies)}, url={url}, interval={interval}"
        if typ == 'load-balance':
            lbp = group.get('strategy') or group.get('strategy-policy') or 'consistent-hashing'
            result += f", strategy={lbp}"
        return result

    if base:
        return base

    # default to select
    if not proxies:
        proxies = ['DIRECT']
    return f"{name} = select, {', '.join(proxies)}"


def to_surge_rules(yaml_obj) -> list[str]:
    rules = yaml_obj.get('rules') or []
    surge_rules = []
    for r in rules:
        # r could be string like: DOMAIN-SUFFIX,google.com,Proxy
        if isinstance(r, str):
            surge_rules.append(r)
        elif isinstance(r, list):
            surge_rules.append(','.join(str(x) for x in r))
    return surge_rules


def generate_surge(yaml_obj) -> str:
    proxies = yaml_obj.get('proxies') or []
    proxy_providers = yaml_obj.get('proxy-providers') or {}
    groups = yaml_obj.get('proxy-groups') or []

    proxy_lines = []
    proxy_names = []

    for p in proxies:
        try:
            line = to_surge_proxy(p)
            proxy_lines.append(line)
            proxy_names.append(p.get('name'))
        except Exception:
            continue

    # proxy providers are not directly supported here; skip

    group_lines = []
    for g in groups:
        try:
            line = to_surge_group(g, proxy_names)
            group_lines.append(line)
        except Exception:
            continue

    rule_lines = to_surge_rules(yaml_obj)

    general = [
        '[General]',
        'ipv6 = true',
        'dns-server = system',
        'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12',
        '',
    ]

    text = []
    text += general
    text += ['[Proxy]']
    text += proxy_lines or ['DIRECT = direct']
    text += ['','[Proxy Group]']
    text += group_lines or ['Proxy = select, DIRECT']
    text += ['','[Rule]']
    if rule_lines:
        text += rule_lines
    else:
        text += ['MATCH, Proxy']
    text += ['']
    return '\n'.join(text)


def main():
    if len(sys.argv) < 3:
        print('Usage: clash_to_surge.py <clash.yml> <surge.conf>')
        sys.exit(2)
    in_path = sys.argv[1]
    out_path = sys.argv[2]

    data = read_yaml(in_path)
    surge = generate_surge(data)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(surge)
    print(f'Wrote {out_path}')

if __name__ == '__main__':
    main()
