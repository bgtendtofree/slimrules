#!/usr/bin/env python3
"""Zero-dependency ruleset builder for Surge and Mihomo."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
DNSMASQ_RE = re.compile(r"^(?:server|address)=/([^/]+)/")
USER_AGENT = "slimrules-builder/1.0"


class TrieNode:
    """Node in a reverse-label domain prefix tree."""

    __slots__ = ("children", "is_exact", "is_suffix")

    def __init__(self) -> None:
        self.children: dict[str, TrieNode] = {}
        self.is_exact: bool = False
        self.is_suffix: bool = False


class DomainTrie:
    """Reverse-label prefix tree for domain deduplication, exclusion, and subtraction."""

    def __init__(self) -> None:
        self.root = TrieNode()

    @staticmethod
    def _labels(domain: str) -> list[str]:
        return domain.split(".")[::-1]

    def add_exact(self, domain: str) -> None:
        """Add an exact domain unless already covered by an ancestor/self suffix."""
        node = self.root
        for label in self._labels(domain):
            if node.is_suffix:
                return
            child = node.children.get(label)
            if child is None:
                child = TrieNode()
                node.children[label] = child
            node = child
        if node.is_suffix:
            return
        node.is_exact = True

    def add_suffix(self, domain: str) -> None:
        """Add a domain suffix, pruning any redundant child exact/suffix rules."""
        node = self.root
        for label in self._labels(domain):
            if node.is_suffix:
                return
            child = node.children.get(label)
            if child is None:
                child = TrieNode()
                node.children[label] = child
            node = child
        node.is_suffix = True
        node.is_exact = False
        node.children.clear()

    def matches(self, domain: str) -> bool:
        """Return True if domain is matched by any suffix or exact rule."""
        node = self.root
        for label in self._labels(domain):
            if node.is_suffix:
                return True
            node = node.children.get(label)  # type: ignore[assignment]
            if node is None:
                return False
        return node.is_suffix or node.is_exact

    def covers_suffix(self, domain: str) -> bool:
        """Return True if domain and all its subdomains are covered by a suffix rule."""
        node = self.root
        for label in self._labels(domain):
            if node.is_suffix:
                return True
            node = node.children.get(label)  # type: ignore[assignment]
            if node is None:
                return False
        return node.is_suffix

    def exclude(self, domain: str, is_suffix: bool) -> None:
        """Remove an exact domain or suffix subtree from the trie."""
        labels = self._labels(domain)
        node = self.root
        parent: TrieNode | None = None
        last_label = ""
        for label in labels:
            if node.is_suffix:
                print(
                    f"[warn] cannot cleanly exclude {domain}: covered by broader suffix ancestor",
                    file=sys.stderr,
                )
                return
            child = node.children.get(label)
            if child is None:
                return
            parent = node
            last_label = label
            node = child

        if is_suffix:
            if parent is not None:
                parent.children.pop(last_label, None)
        else:
            node.is_exact = False

    def subtract(self, other: DomainTrie) -> DomainTrie:
        """Return a new DomainTrie containing rules from self not covered by other."""
        result = DomainTrie()
        exact_domains, suffix_domains = self.dump()
        for domain in suffix_domains:
            if not other.covers_suffix(domain):
                result.add_suffix(domain)
        for domain in exact_domains:
            if not other.matches(domain):
                result.add_exact(domain)
        return result

    def dump(self) -> tuple[list[str], list[str]]:
        """Return deterministically sorted (exact_domains, suffix_domains)."""
        exact: list[str] = []
        suffix: list[str] = []

        def walk(node: TrieNode, rev_labels: list[str]) -> None:
            if node.is_suffix and rev_labels:
                suffix.append(".".join(rev_labels[::-1]))
                return
            if node.is_exact and rev_labels:
                exact.append(".".join(rev_labels[::-1]))
            for label in sorted(node.children.keys()):
                rev_labels.append(label)
                walk(node.children[label], rev_labels)
                rev_labels.pop()

        walk(self.root, [])
        exact.sort()
        suffix.sort()
        return exact, suffix

    def __len__(self) -> int:
        exact, suffix = self.dump()
        return len(exact) + len(suffix)


def strip_comment(line: str) -> str:
    """Strip inline `#` comments and outer whitespace."""
    idx = line.find("#")
    if idx != -1:
        line = line[:idx]
    return line.strip()


def normalize_domain(raw: str) -> str | None:
    """Normalize and validate a domain name; return None if invalid."""
    domain = strip_comment(raw).lower().rstrip(".")
    if not domain or "*" in domain or ".." in domain:
        return None
    labels = domain.split(".")
    for label in labels:
        if not label or not DOMAIN_LABEL_RE.match(label):
            return None
    return domain


def parse_domain_entry(line: str, fmt: str) -> tuple[str, bool] | None:
    """Parse a single non-empty domain rule line into (domain, is_suffix) or None."""
    if fmt == "dnsmasq":
        match = DNSMASQ_RE.match(line)
        if not match:
            return None
        candidate = match.group(1).lstrip(".")
        domain = normalize_domain(candidate)
        return (domain, True) if domain else None

    if fmt == "mihomo_domain":
        if line.startswith("+."):
            domain = normalize_domain(line[2:])
            return (domain, True) if domain else None
        if line.startswith("."):
            domain = normalize_domain(line[1:])
            return (domain, True) if domain else None
        if line.startswith("*."):
            domain = normalize_domain(line[2:])
            return (domain, True) if domain else None
        domain = normalize_domain(line)
        return (domain, False) if domain else None

    if fmt == "auto_domain":
        upper = line.upper()
        if upper.startswith("DOMAIN-SUFFIX,"):
            parts = line.split(",")
            if len(parts) < 2:
                return None
            domain = normalize_domain(parts[1])
            return (domain, True) if domain else None
        if upper.startswith("DOMAIN,"):
            parts = line.split(",")
            if len(parts) < 2:
                return None
            domain = normalize_domain(parts[1])
            return (domain, False) if domain else None
        if line.startswith("domain:"):
            domain = normalize_domain(line[7:])
            return (domain, True) if domain else None
        if line.startswith("full:"):
            domain = normalize_domain(line[5:])
            return (domain, False) if domain else None
        if line.startswith("+."):
            domain = normalize_domain(line[2:])
            return (domain, True) if domain else None
        if line.startswith("."):
            domain = normalize_domain(line[1:])
            return (domain, True) if domain else None
        if line.startswith("*."):
            domain = normalize_domain(line[2:])
            return (domain, True) if domain else None
        domain = normalize_domain(line)
        return (domain, False) if domain else None

    raise ValueError(f"Unsupported domain format: {fmt}")


def parse_domain_lines(lines: Iterable[str], fmt: str) -> tuple[list[tuple[str, bool]], int]:
    """Parse lines into ([(domain, is_suffix), ...], skipped_count)."""
    entries: list[tuple[str, bool]] = []
    skipped = 0
    for raw in lines:
        cleaned = strip_comment(raw)
        if not cleaned:
            continue
        parsed = parse_domain_entry(cleaned, fmt)
        if parsed is None:
            skipped += 1
        else:
            entries.append(parsed)
    return entries, skipped


def parse_ip_lines(
    lines: Iterable[str],
    fmt: str,
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network], int]:
    """Parse IP/CIDR lines or OpenAI JSON into (v4_nets, v6_nets, skipped_count)."""
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_nets: list[ipaddress.IPv6Network] = []
    skipped = 0

    if fmt == "openai_json":
        payload = json.loads("\n".join(lines))
        if not isinstance(payload, dict) or not isinstance(payload.get("prefixes"), list):
            raise ValueError("Invalid openai_json payload: missing prefixes list")
        for item in payload["prefixes"]:
            if not isinstance(item, dict):
                skipped += 1
                continue
            for val in item.values():
                if not isinstance(val, str):
                    skipped += 1
                    continue
                try:
                    net = ipaddress.ip_network(val.strip(), strict=False)
                except ValueError:
                    skipped += 1
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    v4_nets.append(net)
                else:
                    v6_nets.append(net)
        return v4_nets, v6_nets, skipped

    if fmt != "cidr":
        raise ValueError(f"Unsupported IP format: {fmt}")

    for raw in lines:
        cleaned = strip_comment(raw)
        if not cleaned:
            continue
        token = cleaned
        upper = cleaned.upper()
        if upper.startswith("IP-CIDR,") or upper.startswith("IP-CIDR6,"):
            parts = cleaned.split(",")
            if len(parts) < 2:
                skipped += 1
                continue
            token = parts[1].strip()
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            skipped += 1
            continue
        if isinstance(net, ipaddress.IPv4Network):
            v4_nets.append(net)
        else:
            v6_nets.append(net)

    return v4_nets, v6_nets, skipped


def collapse_cidrs(
    v4_nets: Iterable[ipaddress.IPv4Network],
    v6_nets: Iterable[ipaddress.IPv6Network],
) -> tuple[list[str], list[str]]:
    """Collapse overlapping/adjacent IPv4 and IPv6 networks into sorted CIDR strings."""
    collapsed_v4 = [str(net) for net in ipaddress.collapse_addresses(v4_nets)]
    collapsed_v6 = [str(net) for net in ipaddress.collapse_addresses(v6_nets)]
    return collapsed_v4, collapsed_v6


def fetch_text(url: str, cache_dir: Path | None = None) -> str:
    """Fetch remote UTF-8 text with retries and optional disk caching."""
    cache_path: Path | None = None
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_path = cache_dir / f"{digest}.txt"
        if cache_path.exists():
            return cache_path.read_text(encoding="utf-8")

    backoffs = (1, 3)
    last_err: Exception | None = None
    for attempt in range(len(backoffs) + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8")
            if cache_path is not None:
                cache_path.write_text(text, encoding="utf-8")
            return text
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt < len(backoffs):
                time.sleep(backoffs[attempt])

    raise RuntimeError(f"Failed to fetch {url}: {last_err}") from last_err


def load_source_lines(
    source: dict[str, str],
    base_dir: Path,
    cache_dir: Path | None,
) -> list[str]:
    """Load source lines from a local file path or remote URL."""
    if "url" in source:
        return fetch_text(source["url"], cache_dir=cache_dir).splitlines()
    if "path" in source:
        file_path = base_dir / source["path"]
        return file_path.read_text(encoding="utf-8").splitlines()
    raise ValueError(f"Source must specify 'url' or 'path': {source}")


def write_text_file(path: Path, content: str) -> None:
    """Write UTF-8 text ensuring parent directories exist."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def sha256_text(text: str) -> str:
    """Return hex SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def format_surge_header(name: str, description: str, count: int, body_sha256: str) -> str:
    """Format deterministic Surge rule file header without volatile timestamps."""
    return (
        f"# Name: slimrules - {name}\n"
        f"# Description: {description}\n"
        f"# Count: {count}\n"
        f"# SHA256: {body_sha256}\n"
    )


def compile_mrs(mihomo_bin: Path, behavior: str, txt_path: Path, mrs_path: Path) -> None:
    """Compile a Mihomo text ruleset into binary .mrs format."""
    mrs_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(mihomo_bin), "convert-ruleset", behavior, "text", str(txt_path), str(mrs_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"mihomo convert-ruleset failed for {txt_path} (exit {proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )


def build_all(
    config_path: Path,
    output_dir: Path,
    cache_dir: Path | None = None,
    mihomo_bin: Path | None = None,
) -> dict[str, object]:
    """Execute the full ruleset build pipeline and write outputs."""
    base_dir = config_path.resolve().parent
    config = json.loads(config_path.read_text(encoding="utf-8"))
    rulesets_cfg = config.get("rulesets", [])
    if not isinstance(rulesets_cfg, list) or not rulesets_cfg:
        raise ValueError("rules.json must contain a non-empty 'rulesets' list")

    domain_tries: dict[str, DomainTrie] = {}
    manifest_rulesets: dict[str, dict[str, object]] = {}
    summary_rows: list[tuple[str, str, int, int, str]] = []

    for spec in rulesets_cfg:
        name: str = spec["name"]
        rtype: str = spec["type"]
        description: str = spec.get("description", "")
        sources: list[dict[str, str]] = spec.get("sources", [])
        total_skipped = 0

        if rtype == "domain":
            trie = DomainTrie()
            for src in sources:
                lines = load_source_lines(src, base_dir, cache_dir)
                entries, skipped = parse_domain_lines(lines, src["format"])
                total_skipped += skipped
                for domain, is_suffix in entries:
                    if is_suffix:
                        trie.add_suffix(domain)
                    else:
                        trie.add_exact(domain)

            for excl in spec.get("excludes", []):
                parsed = parse_domain_entry(excl, "auto_domain")
                if parsed is not None:
                    trie.exclude(parsed[0], parsed[1])

            for sub_name in spec.get("subtract_rulesets", []):
                if sub_name not in domain_tries:
                    raise ValueError(
                        f"Ruleset '{name}' references '{sub_name}' before it was built"
                    )
                trie = trie.subtract(domain_tries[sub_name])

            exact_domains, suffix_domains = trie.dump()
            count = len(exact_domains) + len(suffix_domains)
            if count == 0:
                raise RuntimeError(f"Ruleset '{name}' produced 0 entries")

            domain_tries[name] = trie

            surge_lines = exact_domains + [f".{d}" for d in suffix_domains]
            surge_body = "\n".join(surge_lines) + "\n"
            body_hash = sha256_text(surge_body)
            surge_rel = Path("surge") / "domainset" / f"{name}.list"
            write_text_file(
                output_dir / surge_rel,
                format_surge_header(name, description, count, body_hash) + surge_body,
            )

            mihomo_lines = exact_domains + [f"+.{d}" for d in suffix_domains]
            mihomo_body = "\n".join(mihomo_lines) + "\n"
            mihomo_txt_rel = Path("mihomo") / "domain" / f"{name}.txt"
            mihomo_txt_path = output_dir / mihomo_txt_rel
            write_text_file(mihomo_txt_path, mihomo_body)

            mrs_rel_str: str | None = None
            mrs_status = "skipped"
            if mihomo_bin is not None:
                mrs_rel = Path("mihomo") / "domain" / f"{name}.mrs"
                compile_mrs(mihomo_bin, "domain", mihomo_txt_path, output_dir / mrs_rel)
                mrs_rel_str = mrs_rel.as_posix()
                mrs_status = "ok"

            entry: dict[str, object] = {
                "type": "domain",
                "count": count,
                "sha256": body_hash,
                "surge": surge_rel.as_posix(),
                "mihomo_text": mihomo_txt_rel.as_posix(),
            }
            if mrs_rel_str is not None:
                entry["mihomo_mrs"] = mrs_rel_str
            manifest_rulesets[name] = entry
            summary_rows.append((name, rtype, count, total_skipped, mrs_status))

        elif rtype == "ip":
            v4_all: list[ipaddress.IPv4Network] = []
            v6_all: list[ipaddress.IPv6Network] = []
            for src in sources:
                lines = load_source_lines(src, base_dir, cache_dir)
                v4_nets, v6_nets, skipped = parse_ip_lines(lines, src["format"])
                total_skipped += skipped
                v4_all.extend(v4_nets)
                v6_all.extend(v6_nets)

            v4_cidrs, v6_cidrs = collapse_cidrs(v4_all, v6_all)
            count = len(v4_cidrs) + len(v6_cidrs)
            if count == 0:
                raise RuntimeError(f"Ruleset '{name}' produced 0 entries")

            no_resolve = bool(spec.get("surge_no_resolve", False))
            suffix = ",no-resolve" if no_resolve else ""
            surge_lines = [f"IP-CIDR,{c}{suffix}" for c in v4_cidrs] + [
                f"IP-CIDR6,{c}{suffix}" for c in v6_cidrs
            ]
            surge_body = "\n".join(surge_lines) + "\n"
            body_hash = sha256_text(surge_body)
            surge_rel = Path("surge") / "ip" / f"{name}.list"
            write_text_file(
                output_dir / surge_rel,
                format_surge_header(name, description, count, body_hash) + surge_body,
            )

            mihomo_lines = v4_cidrs + v6_cidrs
            mihomo_body = "\n".join(mihomo_lines) + "\n"
            mihomo_txt_rel = Path("mihomo") / "ip" / f"{name}.txt"
            mihomo_txt_path = output_dir / mihomo_txt_rel
            write_text_file(mihomo_txt_path, mihomo_body)

            mrs_rel_str = None
            mrs_status = "skipped"
            if mihomo_bin is not None:
                mrs_rel = Path("mihomo") / "ip" / f"{name}.mrs"
                compile_mrs(mihomo_bin, "ipcidr", mihomo_txt_path, output_dir / mrs_rel)
                mrs_rel_str = mrs_rel.as_posix()
                mrs_status = "ok"

            entry = {
                "type": "ip",
                "count": count,
                "sha256": body_hash,
                "surge": surge_rel.as_posix(),
                "mihomo_text": mihomo_txt_rel.as_posix(),
            }
            if mrs_rel_str is not None:
                entry["mihomo_mrs"] = mrs_rel_str
            manifest_rulesets[name] = entry
            summary_rows.append((name, rtype, count, total_skipped, mrs_status))

        else:
            raise ValueError(f"Unsupported ruleset type '{rtype}' for '{name}'")

    manifest: dict[str, object] = {"rulesets": manifest_rulesets}
    write_text_file(
        output_dir / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )

    print(f"{'Ruleset':<14} {'Type':<8} {'Count':>8} {'Skipped':>8} {'MRS':<8}")
    print("-" * 52)
    for row_name, row_type, row_count, row_skipped, row_mrs in summary_rows:
        print(f"{row_name:<14} {row_type:<8} {row_count:>8} {row_skipped:>8} {row_mrs:<8}")

    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Surge and Mihomo rulesets.")
    parser.add_argument("--config", type=Path, default=Path("rules.json"), help="Path to rules.json")
    parser.add_argument("--output", type=Path, default=Path("dist"), help="Output directory")
    parser.add_argument("--cache-dir", type=Path, default=None, help="Optional upstream cache dir")
    parser.add_argument("--mihomo-bin", type=Path, default=None, help="Path to mihomo binary for .mrs compilation")
    args = parser.parse_args(argv)

    if args.mihomo_bin is not None and not args.mihomo_bin.is_file():
        print(f"Error: mihomo binary not found at {args.mihomo_bin}", file=sys.stderr)
        return 1

    build_all(
        config_path=args.config,
        output_dir=args.output,
        cache_dir=args.cache_dir,
        mihomo_bin=args.mihomo_bin,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
