"""Evidence-focused tests for deterministic security analysis."""

from copy import deepcopy

import pytest

from linuxmd.diagnostics.evidence import classify_bind_address
from linuxmd.diagnostics.security import analyze_security


@pytest.fixture
def facts() -> dict:
    sections = {
        name: {"status": "available"}
        for name in (
            "platform_security",
            "cpu_security",
            "virtualization_security",
            "iommu_pcie_security",
            "kernel_hardening",
            "firewall_network_exposure",
            "storage_filesystem_security",
            "identity_access",
            "updates",
            "container_security",
        )
    }
    sections.update(
        {
            "collector": "security",
            "errors": [],
            "platform_security": {"status": "available", "secure_boot": {"state": "enabled"}},
            "cpu_security": {"status": "available", "vulnerabilities": {}},
            "virtualization_security": {"status": "available", "environment": "bare_metal"},
            "iommu_pcie_security": {
                "status": "available",
                "applicable": True,
                "observable": True,
                "enabled": True,
                "value": True,
                "evidence_source": "test fixture",
            },
            "kernel_hardening": {
                "status": "available",
                "selinux": {"supported": True, "state": "enforcing"},
                "apparmor": {"supported": False, "enabled": False},
                "sysctls": {},
            },
            "firewall_network_exposure": {
                "status": "available",
                "nftables": {"status": "available", "active_ruleset": True},
                "iptables": {"status": "available"},
                "firewalld": {"status": "unavailable"},
                "ufw": {"status": "unavailable"},
                "listening_sockets": [],
            },
            "storage_filesystem_security": {
                "status": "available",
                "root_encrypted": None,
                "encryption_detection_status": "available",
            },
            "identity_access": {"status": "available", "ssh_server": {"settings": {}}},
        }
    )
    return sections


def test_unknown_data_does_not_produce_false_findings() -> None:
    result = analyze_security({"collector": "security", "errors": []})

    assert result["critical_findings"] == []
    assert result["high_findings"] == []
    assert result["medium_findings"] == []
    assert result["unknowns_and_gaps"]


def test_false_iommu_with_unknown_applicability_is_not_a_finding(facts) -> None:
    facts["iommu_pcie_security"].update(
        {"enabled": False, "value": False, "applicable": None, "observable": True}
    )

    result = analyze_security(facts)

    assert not any("IOMMU" in item for item in result["medium_findings"])
    assert any("IOMMU state is not assessable" in item for item in result["unknowns_and_gaps"])


def test_false_iommu_with_confirmed_applicability_may_be_a_finding(facts) -> None:
    facts["iommu_pcie_security"].update(
        {"enabled": False, "value": False, "applicable": True, "observable": True}
    )

    result = analyze_security(facts)

    assert any("iommu_pcie_security.enabled=False" in item for item in result["medium_findings"])


@pytest.mark.parametrize(
    "mutation,field,severity",
    [
        (
            ("platform_security", "secure_boot", "state", "disabled"),
            "secure_boot.state=disabled",
            "medium_findings",
        ),
        (
            ("iommu_pcie_security", "enabled", None, False),
            "iommu_pcie_security.enabled=False",
            "medium_findings",
        ),
        (
            ("kernel_hardening", "selinux", "state", "permissive"),
            "selinux.state=permissive",
            "medium_findings",
        ),
        (
            ("kernel_hardening", "sysctls", "dmesg_restrict", "0"),
            "dmesg_restrict=0",
            "medium_findings",
        ),
        (
            ("identity_access", "ssh_server", "permitrootlogin", "yes"),
            "permitrootlogin=yes",
            "high_findings",
        ),
        (
            ("identity_access", "ssh_server", "passwordauthentication", "yes"),
            "passwordauthentication=yes",
            "medium_findings",
        ),
    ],
)
def test_findings_reference_collected_evidence(facts, mutation, field, severity) -> None:
    data = deepcopy(facts)
    section, group, key, value = mutation
    if section == "identity_access":
        data[section][group]["settings"][key] = value
    elif key is None:
        data[section][group] = value
    else:
        data[section][group][key] = value

    result = analyze_security(data)

    assert any(field in finding for finding in result[severity])
    assert any(field in item for item in result["supporting_evidence"])


def test_vulnerable_cpu_status_is_high(facts) -> None:
    facts["cpu_security"]["vulnerabilities"] = {"spectre_v2": "Vulnerable: no microcode"}

    result = analyze_security(facts)

    assert "cpu_security.vulnerabilities.spectre_v2=Vulnerable" in result["high_findings"][0]


def test_localhost_listener_is_not_world_facing(facts) -> None:
    facts["firewall_network_exposure"]["listening_sockets"] = [
        {"protocol": "tcp", "bind_address": "127.0.0.1", "port": 8080, "process": "dev"}
    ]

    result = analyze_security(facts)

    assert not any("wildcard-bound" in item for item in result["medium_findings"])
    assert any("loopback-bound" in item for item in result["supporting_evidence"])


@pytest.mark.parametrize(
    ("address", "classification"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.255.255.254", "private/internal"),
        ("0.0.0.0", "wildcard"),
    ],
)
def test_bind_address_classification(address, classification) -> None:
    assert classify_bind_address(address) == classification


def test_internal_wsl_address_is_not_described_as_localhost(facts) -> None:
    facts["firewall_network_exposure"]["listening_sockets"] = [
        {"protocol": "tcp", "bind_address": "10.255.255.254", "port": 53}
    ]

    result = analyze_security(facts)

    assert "localhost" not in " ".join(result["supporting_evidence"]).lower()
    assert any("internal addresses" in item for item in result["supporting_evidence"])


def test_tdx_host_msr_is_not_applicable_in_wsl2(facts) -> None:
    facts["virtualization_security"]["environment"] = "wsl2"
    facts["cpu_security"]["vendor_security"] = {
        "intel": {
            "tdx": {
                "status": "available",
                "privileged_register_verification": {
                    "observations": {"tdx_enabled": {"status": "missing_tool"}}
                },
            }
        }
    }

    result = analyze_security(facts)

    assert {
        "check": "cpu_security.vendor_security.intel.tdx.host_msr_verification",
        "status": "not_applicable",
    } in result["applicability"]
    assert not any("tdx_enabled" in gap for gap in result["unknowns_and_gaps"])


def test_security_summary_uses_bounded_compromise_wording(facts) -> None:
    summary = analyze_security(facts)["security_summary"]

    assert "No evidence of active compromise was found" in summary
    assert "No active compromise detected" not in summary


def test_wildcard_listener_without_firewall_is_contextual_risk(facts) -> None:
    facts["firewall_network_exposure"]["nftables"]["active_ruleset"] = False
    facts["firewall_network_exposure"]["listening_sockets"] = [
        {"protocol": "tcp", "bind_address": "0.0.0.0", "port": 8080, "process": "web"}
    ]

    result = analyze_security(facts)

    assert any("wildcard-bound" in item for item in result["medium_findings"])
    assert not any(
        "malicious" in item
        for values in result.values()
        if isinstance(values, list)
        for item in values
    )


def test_encrypted_root_is_informational(facts) -> None:
    facts["storage_filesystem_security"]["root_encrypted"] = True

    result = analyze_security(facts)

    assert any("root_encrypted=True" in item for item in result["low_findings"])
