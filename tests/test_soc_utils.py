"""Tests for the SOC utilities service (IOC parsing/generation, log parsing)."""

from __future__ import annotations

import json

from zorksec.services.soc_utils_service import (
    SocUtilsService,
    analyze_pcap,
    generate_iocs,
    parse_iocs,
    parse_logs,
    refang,
)


def test_refang_normalises_defanged_indicators():
    assert refang("hxxp://evil[.]test") == "http://evil.test"
    assert refang("bob[at]mail[.]com") == "bob@mail.com"


def test_parse_iocs_extracts_all_types():
    text = ("Saw hxxp://malware[.]test/x.bin from 203.0.113.45, mailed by "
            "evil@bad-example.com, hash 44d88612fea8a8f36de82e1278abb02f, "
            "pivot domain good-example.org")
    iocs = parse_iocs(text)
    assert "203.0.113.45" in iocs.ips
    assert "http://malware.test/x.bin" in iocs.urls
    assert "evil@bad-example.com" in iocs.emails
    assert "44d88612fea8a8f36de82e1278abb02f" in iocs.hashes
    assert "good-example.org" in iocs.domains
    # Domains inside URLs/emails are not double-counted.
    assert "malware.test" not in iocs.domains
    assert "bad-example.com" not in iocs.domains


def test_parse_iocs_total_count():
    iocs = parse_iocs("1.2.3.4 and 5.6.7.8")
    assert iocs.total == 2


def test_generate_iocs_csv_and_json():
    csv_out = generate_iocs(["203.0.113.45", "evil-example.test"], "csv")
    assert "indicator,type,context" in csv_out
    assert "203.0.113.45,ip" in csv_out

    json_out = generate_iocs(["203.0.113.45"], "json")
    bundle = json.loads(json_out)
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["value"] == "203.0.113.45"


def test_generate_iocs_invalid_format_raises():
    import pytest
    with pytest.raises(ValueError):
        generate_iocs(["1.2.3.4"], "xml")


def test_parse_logs_detects_formats():
    logs = "\n".join([
        "Jan 10 10:00:00 host sshd[123]: Failed password for root",
        '127.0.0.1 - - [10/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 12',
        '{"event":"login","user":"a"}',
        "user=bob action=delete",
    ])
    result = parse_logs(logs)
    assert result["count"] == 4
    assert result["formats"]["syslog"] == 1
    assert result["formats"]["clf"] == 1
    assert result["formats"]["json"] == 1
    assert result["formats"]["keyvalue"] == 1


def test_analyze_pcap_missing_file_is_graceful():
    result = analyze_pcap("/nonexistent/file.pcap")
    assert result["available"] is False
    assert "not found" in result["error"].lower()


def test_integrations_exposes_links():
    links = SocUtilsService.integrations()
    assert "cyberchef" in links and links["cyberchef"].startswith("http")
    assert "attack_navigator" in links
