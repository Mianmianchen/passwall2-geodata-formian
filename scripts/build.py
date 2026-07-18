#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work" / "sources"
DIST = ROOT / "dist"
SOURCES = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))


def protobuf_types():
    fd = descriptor_pb2.FileDescriptorProto()
    fd.name = "routercommon.proto"
    fd.package = "v2ray.core.app.router.routercommon"
    fd.syntax = "proto3"

    msg = fd.message_type.add(); msg.name = "Domain"
    enum = msg.enum_type.add(); enum.name = "Type"
    for name, num in [("Plain", 0), ("Regex", 1), ("RootDomain", 2), ("Full", 3)]:
        value = enum.value.add(); value.name = name; value.number = num
    field = msg.field.add(); field.name = "type"; field.number = 1; field.label = 1; field.type = 14
    field.type_name = ".v2ray.core.app.router.routercommon.Domain.Type"
    field = msg.field.add(); field.name = "value"; field.number = 2; field.label = 1; field.type = 9

    msg = fd.message_type.add(); msg.name = "CIDR"
    field = msg.field.add(); field.name = "ip"; field.number = 1; field.label = 1; field.type = 12
    field = msg.field.add(); field.name = "prefix"; field.number = 2; field.label = 1; field.type = 13

    msg = fd.message_type.add(); msg.name = "GeoIP"
    field = msg.field.add(); field.name = "country_code"; field.number = 1; field.label = 1; field.type = 9
    field = msg.field.add(); field.name = "cidr"; field.number = 2; field.label = 3; field.type = 11
    field.type_name = ".v2ray.core.app.router.routercommon.CIDR"
    field = msg.field.add(); field.name = "inverse_match"; field.number = 3; field.label = 1; field.type = 8

    msg = fd.message_type.add(); msg.name = "GeoIPList"
    field = msg.field.add(); field.name = "entry"; field.number = 1; field.label = 3; field.type = 11
    field.type_name = ".v2ray.core.app.router.routercommon.GeoIP"

    msg = fd.message_type.add(); msg.name = "GeoSite"
    field = msg.field.add(); field.name = "country_code"; field.number = 1; field.label = 1; field.type = 9
    field = msg.field.add(); field.name = "domain"; field.number = 2; field.label = 3; field.type = 11
    field.type_name = ".v2ray.core.app.router.routercommon.Domain"

    msg = fd.message_type.add(); msg.name = "GeoSiteList"
    field = msg.field.add(); field.name = "entry"; field.number = 1; field.label = 3; field.type = 11
    field.type_name = ".v2ray.core.app.router.routercommon.GeoSite"

    pool = descriptor_pool.DescriptorPool(); pool.Add(fd)
    site = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("v2ray.core.app.router.routercommon.GeoSiteList")
    )
    ip = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("v2ray.core.app.router.routercommon.GeoIPList")
    )
    return site, ip


GeoSiteList, GeoIPList = protobuf_types()


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "passwall2-custom-geodata-builder/1.0"},
            )
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read()
            if not data:
                raise RuntimeError("download returned an empty file")
            destination.write_bytes(data)
            return
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(attempt * 3)
    raise RuntimeError(f"failed to download {url}: {last_error}")


def add_domain(bucket: set[tuple[int, str]], domain_type: int, value: str) -> None:
    value = value.strip().strip("\"'").rstrip(".")
    if not value:
        return
    if value.startswith("+."):
        domain_type, value = 2, value[2:]
    elif value.startswith("."):
        domain_type, value = 2, value[1:]
    bucket.add((domain_type, value.lower()))


def parse_rule(line: str, domains: set[tuple[int, str]], cidrs: set[str], ignored: Counter) -> None:
    parts = [part.strip() for part in line.split(",")]
    kind = parts[0].upper()
    value = parts[1] if len(parts) > 1 else ""

    if kind == "DOMAIN":
        add_domain(domains, 3, value)
    elif kind == "DOMAIN-SUFFIX":
        add_domain(domains, 2, value)
    elif kind == "DOMAIN-KEYWORD":
        add_domain(domains, 0, value)
    elif kind in ("DOMAIN-REGEX", "HOST-REGEX"):
        add_domain(domains, 1, value)
    elif kind in ("IP-CIDR", "IP-CIDR6"):
        try:
            cidrs.add(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            ignored["INVALID_CIDR"] += 1
    elif kind in {
        "USER-AGENT", "URL-REGEX", "IP-ASN", "PROCESS-NAME", "PROCESS-PATH",
        "AND", "OR", "NOT", "DST-PORT", "SRC-PORT", "NETWORK", "RULE-SET",
        "FINAL", "MATCH"
    }:
        ignored[kind] += 1
    elif re.fullmatch(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+", line):
        add_domain(domains, 3, line)
    else:
        ignored[kind or "UNKNOWN"] += 1


def parse_source(path: Path):
    domains: set[tuple[int, str]] = set()
    cidrs: set[str] = set()
    ignored: Counter = Counter()
    in_yaml_payload = False

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("payload:", "rules:"):
            in_yaml_payload = True
            continue
        if line.startswith("- "):
            value = line[2:].strip().split(" #", 1)[0].strip().strip("\"'")
            if "," in value and value.split(",", 1)[0].upper() in {
                "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "HOST-REGEX",
                "IP-CIDR", "IP-CIDR6", "USER-AGENT", "URL-REGEX", "IP-ASN", "AND", "OR",
                "NOT", "DST-PORT", "SRC-PORT", "NETWORK", "RULE-SET", "FINAL", "MATCH"
            }:
                parse_rule(value, domains, cidrs, ignored)
            else:
                add_domain(domains, 2 if value.startswith(("+.", ".")) else 3, value)
            continue
        parse_rule(line, domains, cidrs, ignored)

    return domains, cidrs, ignored


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    DIST.mkdir(parents=True, exist_ok=True)

    site_data = {}
    ip_data = {}
    per_tag = {}
    ignored_total: Counter = Counter()

    for tag, url in SOURCES.items():
        source_file = WORK / f"{tag}.txt"
        print(f"Downloading {tag} ...")
        download(url, source_file)
        domains, cidrs, ignored = parse_source(source_file)
        if not domains and not cidrs:
            raise RuntimeError(f"source {tag} produced no usable rules")
        site_data[tag] = domains
        ip_data[tag] = cidrs
        per_tag[tag] = (len(domains), len(cidrs), dict(ignored))
        ignored_total.update(ignored)

    sites = GeoSiteList()
    for tag in SOURCES:
        values = site_data[tag]
        if not values:
            continue
        entry = sites.entry.add(); entry.country_code = tag.upper()
        for domain_type, value in sorted(values, key=lambda item: (item[0], item[1])):
            domain = entry.domain.add(); domain.type = domain_type; domain.value = value

    ips = GeoIPList()
    for tag in SOURCES:
        values = ip_data[tag]
        if not values:
            continue
        entry = ips.entry.add(); entry.country_code = tag.upper()
        networks = sorted(
            (ipaddress.ip_network(value, strict=False) for value in values),
            key=lambda net: (net.version, int(net.network_address), net.prefixlen),
        )
        for network in networks:
            cidr = entry.cidr.add(); cidr.ip = network.network_address.packed; cidr.prefix = network.prefixlen

    site_path = DIST / "mianmian-geosite.dat"
    ip_path = DIST / "mianmian-geoip.dat"
    site_path.write_bytes(sites.SerializeToString())
    ip_path.write_bytes(ips.SerializeToString())

    # Protobuf round-trip validation.
    verify_site = GeoSiteList(); verify_site.ParseFromString(site_path.read_bytes())
    verify_ip = GeoIPList(); verify_ip.ParseFromString(ip_path.read_bytes())

    built_at = datetime.now(timezone.utc).isoformat()
    report_path = DIST / "build-report.txt"
    with report_path.open("w", encoding="utf-8") as report:
        report.write(f"Built at: {built_at}\n")
        report.write(f"GeoSite tags: {len(verify_site.entry)}, domains: {sum(len(e.domain) for e in verify_site.entry)}\n")
        report.write(f"GeoIP tags: {len(verify_ip.entry)}, CIDRs: {sum(len(e.cidr) for e in verify_ip.entry)}\n\n")
        for tag, (domain_count, cidr_count, ignored) in per_tag.items():
            report.write(f"{tag}: domain={domain_count}, cidr={cidr_count}, ignored={ignored}\n")
        report.write("\nIgnored rule types total:\n")
        for kind, count in ignored_total.most_common():
            report.write(f"{kind}: {count}\n")

    checksum_path = DIST / "SHA256SUMS"
    with checksum_path.open("w", encoding="utf-8") as checksum_file:
        for path in (site_path, ip_path, report_path):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            checksum_file.write(f"{digest}  {path.name}\n")

    notes = DIST / "release-notes.md"
    notes.write_text(
        f"Automated Xray geodata build.\n\nBuilt at: `{built_at}`\n\n"
        "Assets: `mianmian-geosite.dat`, `mianmian-geoip.dat`, `SHA256SUMS`, `build-report.txt`.\n",
        encoding="utf-8",
    )
    print(report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
