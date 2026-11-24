from __future__ import annotations

import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build  # noqa: E402


class TestDomainTrie(unittest.TestCase):
    def test_deduplication_exact_and_suffix(self) -> None:
        trie = build.DomainTrie()
        trie.add_exact("a.google.com")
        trie.add_exact("b.google.com")
        trie.add_suffix("google.com")
        trie.add_exact("c.google.com")
        trie.add_suffix("sub.google.com")

        exact, suffix = trie.dump()
        self.assertEqual(exact, [])
        self.assertEqual(suffix, ["google.com"])

    def test_exact_siblings_coexist(self) -> None:
        trie = build.DomainTrie()
        trie.add_exact("example.com")
        trie.add_exact("sub.example.com")

        exact, suffix = trie.dump()
        self.assertEqual(exact, ["example.com", "sub.example.com"])
        self.assertEqual(suffix, [])

    def test_exclude_suffix_subtree(self) -> None:
        trie = build.DomainTrie()
        trie.add_suffix("apps.apple.com")
        trie.add_suffix("amp-api-updates.apps.apple.com")
        trie.add_exact("apps.apple.com")
        trie.add_suffix("mzstatic.com")
        trie.add_exact("apple.com")

        trie.exclude("apps.apple.com", is_suffix=True)
        exact, suffix = trie.dump()
        self.assertEqual(exact, ["apple.com"])
        self.assertEqual(suffix, ["mzstatic.com"])

    def test_subtract_google_from_ai(self) -> None:
        google = build.DomainTrie()
        google.add_suffix("google.com")
        google.add_suffix("googleapis.com")
        google.add_suffix("deepmind.com")
        google.add_exact("ai.google.dev")
        google.add_suffix("antigravity.google")

        ai = build.DomainTrie()
        ai.add_exact("gemini.google.com")
        ai.add_suffix("bard.google.com")
        ai.add_exact("generativelanguage.googleapis.com")
        ai.add_exact("ai.google.dev")
        ai.add_suffix("deepmind.com")
        ai.add_exact("antigravity.google")
        ai.add_suffix("openai.com")
        ai.add_suffix("claude.ai")
        ai.add_exact("openrouter.ai")

        ai_clean = ai.subtract(google)
        exact, suffix = ai_clean.dump()
        self.assertEqual(exact, ["openrouter.ai"])
        self.assertEqual(suffix, ["claude.ai", "openai.com"])


class TestParsersAndCidrs(unittest.TestCase):
    def test_mihomo_domain_parser(self) -> None:
        lines = [
            "# comment",
            "+.example.com",
            "exact.example.org",
            "*.cdn.example.net",
            "foo.*.bar.com",
            "invalid..domain",
        ]
        entries, skipped = build.parse_domain_lines(lines, "mihomo_domain")
        self.assertEqual(
            entries,
            [
                ("example.com", True),
                ("exact.example.org", False),
                ("cdn.example.net", True),
            ],
        )
        self.assertEqual(skipped, 2)

    def test_auto_domain_parser(self) -> None:
        lines = [
            "DOMAIN,api.example.com # inline comment",
            "DOMAIN-SUFFIX,openai.com",
            "+.claude.ai",
            ".anthropic.com",
            "full:exact.test",
            "domain:suffix.test",
            "bare.example.org",
        ]
        entries, skipped = build.parse_domain_lines(lines, "auto_domain")
        self.assertEqual(skipped, 0)
        self.assertEqual(
            entries,
            [
                ("api.example.com", False),
                ("openai.com", True),
                ("claude.ai", True),
                ("anthropic.com", True),
                ("exact.test", False),
                ("suffix.test", True),
                ("bare.example.org", False),
            ],
        )

    def test_dnsmasq_parser(self) -> None:
        lines = [
            "# apple.china.conf",
            "server=/amp-api-updates.apps.apple.com/114.114.114.114",
            "address=/.mzstatic.com/114.114.114.114",
        ]
        entries, skipped = build.parse_domain_lines(lines, "dnsmasq")
        self.assertEqual(skipped, 0)
        self.assertEqual(
            entries,
            [
                ("amp-api-updates.apps.apple.com", True),
                ("mzstatic.com", True),
            ],
        )

    def test_cidr_and_openai_json_and_collapse(self) -> None:
        v4, v6, skipped = build.parse_ip_lines(
            [
                "# comment",
                "10.0.0.0/25",
                "10.0.0.128/25",
                "192.168.1.5",
                "IP-CIDR,172.16.0.0/16,no-resolve",
                "IP-CIDR6,2001:db8::/32,no-resolve",
                "not-an-ip",
            ],
            "cidr",
        )
        self.assertEqual(skipped, 1)
        json_v4, json_v6, json_skipped = build.parse_ip_lines(
            [
                json.dumps(
                    {
                        "creationTime": "2026-11-16T00:00:00Z",
                        "prefixes": [
                            {"ipv4Prefix": "104.211.223.134/32"},
                            {"ipv6Prefix": "2001:db8:1::/48"},
                        ],
                    }
                )
            ],
            "openai_json",
        )
        self.assertEqual(json_skipped, 0)

        collapsed_v4, collapsed_v6 = build.collapse_cidrs(
            v4 + json_v4,
            v6 + json_v6,
        )
        self.assertEqual(
            collapsed_v4,
            ["10.0.0.0/24", "104.211.223.134/32", "172.16.0.0/16", "192.168.1.5/32"],
        )
        self.assertEqual(collapsed_v6, ["2001:db8::/32"])
        self.assertTrue(all(isinstance(ipaddress.ip_network(c), ipaddress.IPv4Network) for c in collapsed_v4))


class TestEndToEndLocalBuild(unittest.TestCase):
    def test_deterministic_end_to_end_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            fixtures.mkdir()

            (fixtures / "apple.china.conf").write_text(
                "server=/amp-api-updates.apps.apple.com/114.114.114.114\n"
                "server=/mzstatic.com/114.114.114.114\n"
                "server=/push.apple.com/114.114.114.114\n",
                encoding="utf-8",
            )
            (fixtures / "google.list").write_text(
                "+.google.com\n+.googleapis.com\n+.youtube.com\n",
                encoding="utf-8",
            )
            (fixtures / "ai.list").write_text(
                "gemini.google.com\ngenerativelanguage.googleapis.com\n+.openai.com\nopenrouter.ai\n",
                encoding="utf-8",
            )
            (fixtures / "ai_voice.json").write_text(
                json.dumps({"prefixes": [{"ipv4Prefix": "13.71.25.29/32"}]}),
                encoding="utf-8",
            )
            (fixtures / "cn.txt").write_text("1.1.8.0/24\n2001:250::/30\n", encoding="utf-8")

            config = {
                "rulesets": [
                    {
                        "name": "apple_cdn",
                        "type": "domain",
                        "description": "Apple CDN",
                        "sources": [{"path": "fixtures/apple.china.conf", "format": "dnsmasq"}],
                        "excludes": [".apps.apple.com", ".push.apple.com"],
                    },
                    {
                        "name": "google",
                        "type": "domain",
                        "description": "Google",
                        "sources": [{"path": "fixtures/google.list", "format": "mihomo_domain"}],
                    },
                    {
                        "name": "ai",
                        "type": "domain",
                        "description": "AI",
                        "sources": [{"path": "fixtures/ai.list", "format": "mihomo_domain"}],
                        "subtract_rulesets": ["google"],
                    },
                    {
                        "name": "ai_ip",
                        "type": "ip",
                        "surge_no_resolve": True,
                        "description": "AI IP",
                        "sources": [{"path": "fixtures/ai_voice.json", "format": "openai_json"}],
                    },
                    {
                        "name": "cn_ip",
                        "type": "ip",
                        "surge_no_resolve": False,
                        "description": "CN IP",
                        "sources": [{"path": "fixtures/cn.txt", "format": "cidr"}],
                    },
                ]
            }
            config_path = root / "rules.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            out1 = root / "dist1"
            out2 = root / "dist2"
            build.build_all(config_path, out1)
            build.build_all(config_path, out2)

            # Verify apple_cdn exclusion
            apple_surge = (out1 / "surge/domainset/apple_cdn.list").read_text(encoding="utf-8")
            self.assertNotIn("apps.apple.com", apple_surge)
            self.assertNotIn("push.apple.com", apple_surge)
            self.assertIn("\n.mzstatic.com\n", apple_surge)
            self.assertNotIn("+.", apple_surge)

            # Verify ai subtracted google
            ai_mihomo = (out1 / "mihomo/domain/ai.txt").read_text(encoding="utf-8")
            self.assertNotIn("#", ai_mihomo)
            self.assertNotIn("google", ai_mihomo)
            self.assertEqual(ai_mihomo.splitlines(), ["openrouter.ai", "+.openai.com"])

            # Verify no-resolve flags
            ai_ip_surge = (out1 / "surge/ip/ai_ip.list").read_text(encoding="utf-8")
            cn_ip_surge = (out1 / "surge/ip/cn_ip.list").read_text(encoding="utf-8")
            self.assertIn("IP-CIDR,13.71.25.29/32,no-resolve\n", ai_ip_surge)
            self.assertIn("IP-CIDR,1.1.8.0/24\n", cn_ip_surge)
            self.assertNotIn("no-resolve", cn_ip_surge)
            self.assertIn("IP-CIDR6,2001:250::/30\n", cn_ip_surge)

            # Verify deterministic re-run
            for rel in (
                "manifest.json",
                "surge/domainset/ai.list",
                "mihomo/domain/ai.txt",
                "surge/ip/cn_ip.list",
                "mihomo/ip/cn_ip.txt",
            ):
                self.assertEqual(
                    (out1 / rel).read_bytes(),
                    (out2 / rel).read_bytes(),
                )

    def test_compile_mrs_resolves_relative_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "mihomo"
            fake_bin.write_text("#!/bin/sh\necho ok > \"$5\"\n", encoding="utf-8")
            fake_bin.chmod(0o755)

            txt = root / "in.txt"
            txt.write_text("+.openai.com\n", encoding="utf-8")
            mrs = root / "out.mrs"

            import os

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                build.compile_mrs(Path("./mihomo"), "domain", txt, mrs)
            finally:
                os.chdir(old_cwd)

            self.assertEqual(mrs.read_text(encoding="utf-8").strip(), "ok")


if __name__ == "__main__":
    unittest.main()
