"""内外网地址判定（修复 startswith 前缀法的双向失效）。

原实现用 `destination.startswith(("internal://", "localhost"))` 判定是否内部地址，
导致两个方向的错误：
- `localhost.evil.com` 被判为内部 → 绕过检测（漏报）；
- `https://localhost:8443` 真实 URL 带 scheme 前缀 → 被判为外部（误报）。

现按 URL 结构解析后比较主机名：scheme 无关、端口无关、覆盖回环地址、
RFC1918 私网地址与常见内部域名后缀。
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_INTERNAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
_INTERNAL_SCHEMES = {"internal", "local", "memory", "file"}
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".svc.cluster.local")

_PRIVATE_NETS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
)

_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+(:\d+)?$")


def extract_host(destination: str) -> str:
    """从任意形态的目标串中提取主机名（小写，去端口）。"""
    dest = (destination or "").strip()
    if not dest:
        return ""
    if "://" in dest:
        host = urlparse(dest).hostname or ""
    else:
        # 无 scheme 时兼容 "host:port" / "host/path" 两种写法
        candidate = dest.split("/")[0]
        host = candidate.rsplit(":", 1)[0] if _HOST_RE.match(candidate) else candidate
    return host.lower().rstrip(".")


def is_internal_destination(destination: str) -> bool:
    """是否为内部/受信目的地址。"""
    dest = (destination or "").strip()
    if not dest:
        return True  # 无显式目的地址视为不出网
    scheme = dest.split("://", 1)[0].lower() if "://" in dest else ""
    if scheme in _INTERNAL_SCHEMES:
        return True
    host = extract_host(dest)
    if not host:
        return True
    if host in _INTERNAL_HOSTS or any(host.endswith(sfx) for sfx in _INTERNAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # 非 IP：主机名类外部域名（localhost.evil.com 在此正确判为外部）
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def is_external_destination(destination: str) -> bool:
    """是否为外部地址（需做数据外发检测）。"""
    return not is_internal_destination(destination)
