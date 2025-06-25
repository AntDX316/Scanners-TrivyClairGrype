#!/usr/bin/env python3
"""
Test script to generate mock vulnerability data for all three scanners
to see how the HTML report looks with actual results.
"""

import json
import os
from pathlib import Path
from datetime import datetime

def create_mock_trivy_data():
    """Create mock Trivy results with vulnerabilities"""
    return {
        "SchemaVersion": 2,
        "ArtifactName": "test-app",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "package.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44906",
                        "PkgName": "minimist",
                        "InstalledVersion": "1.2.5",
                        "FixedVersion": "1.2.6",
                        "Severity": "CRITICAL",
                        "Description": "Prototype pollution vulnerability in minimist package allowing remote code execution through malicious command line arguments."
                    },
                    {
                        "VulnerabilityID": "CVE-2022-0691",
                        "PkgName": "url-parse",
                        "InstalledVersion": "1.5.1",
                        "FixedVersion": "1.5.10",
                        "Severity": "HIGH",
                        "Description": "Authorization bypass through user-controlled key vulnerability in url-parse package."
                    },
                    {
                        "VulnerabilityID": "CVE-2021-3807",
                        "PkgName": "ansi-regex",
                        "InstalledVersion": "3.0.0",
                        "FixedVersion": "5.0.1",
                        "Severity": "MEDIUM",
                        "Description": "Regular expression denial of service (ReDoS) vulnerability in ansi-regex package."
                    },
                    {
                        "VulnerabilityID": "CVE-2020-28469",
                        "PkgName": "glob-parent",
                        "InstalledVersion": "5.1.1",
                        "FixedVersion": "5.1.2",
                        "Severity": "LOW",
                        "Description": "Regular expression denial of service vulnerability in glob-parent package."
                    }
                ]
            }
        ]
    }

def create_mock_grype_data():
    """Create mock Grype results with vulnerabilities"""
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-1234",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                    "severity": "Critical",
                    "description": "Buffer overflow vulnerability in libssl allowing remote code execution through crafted TLS handshake."
                },
                "artifact": {
                    "name": "libssl1.1",
                    "version": "1.1.1f-1ubuntu2.16",
                    "type": "deb",
                    "locations": [{"path": "/var/lib/dpkg/status"}]
                },
                "matchDetails": [
                    {
                        "type": "exact-direct-match",
                        "matcher": "dpkg-matcher",
                        "searchedBy": {"distro": {"type": "ubuntu", "version": "20.04"}}
                    }
                ]
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-5678",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
                    "severity": "High",
                    "description": "SQL injection vulnerability in database connector allowing unauthorized data access."
                },
                "artifact": {
                    "name": "mysql-connector",
                    "version": "8.0.25",
                    "type": "python",
                    "locations": [{"path": "/usr/local/lib/python3.8/site-packages"}]
                },
                "matchDetails": [
                    {
                        "type": "exact-direct-match",
                        "matcher": "python-matcher"
                    }
                ]
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-9012",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-9012",
                    "severity": "Medium",
                    "description": "Cross-site scripting (XSS) vulnerability in web framework template engine."
                },
                "artifact": {
                    "name": "jinja2",
                    "version": "2.11.3",
                    "type": "python",
                    "locations": [{"path": "/usr/local/lib/python3.8/site-packages"}]
                },
                "matchDetails": [
                    {
                        "type": "exact-direct-match",
                        "matcher": "python-matcher"
                    }
                ]
            }
        ]
    }

def create_mock_clair_data():
    """Create mock Clair results with vulnerabilities"""
    return {
        "Vulnerabilities": [
            {
                "Name": "CVE-2023-4567",
                "FeatureName": "openssl",
                "FeatureVersion": "1.1.1k-1",
                "Severity": "Critical",
                "Description": "Memory corruption vulnerability in OpenSSL cryptographic library allowing remote code execution through malformed certificates. This vulnerability affects the certificate parsing functionality and can be exploited by attackers to gain unauthorized access to systems."
            },
            {
                "Name": "CVE-2023-7890",
                "FeatureName": "curl",
                "FeatureVersion": "7.68.0-1ubuntu2.14",
                "Severity": "High",
                "Description": "Heap buffer overflow in curl HTTP client library when processing malformed HTTP headers. Attackers can exploit this vulnerability to execute arbitrary code or cause denial of service."
            },
            {
                "Name": "CVE-2023-1357",
                "FeatureName": "zlib",
                "FeatureVersion": "1.2.11.dfsg-2ubuntu1.3",
                "Severity": "Medium",
                "Description": "Integer overflow vulnerability in zlib compression library leading to potential buffer overflow conditions during data compression operations."
            },
            {
                "Name": "CVE-2023-2468",
                "FeatureName": "libc6",
                "FeatureVersion": "2.31-0ubuntu9.9",
                "Severity": "Low",
                "Description": "Information disclosure vulnerability in GNU C Library allowing local users to read sensitive memory contents through crafted system calls."
            }
        ]
    }

def main():
    """Generate mock data and create a test report"""
    print("🧪 Creating mock vulnerability data for testing...")
    
    # Create results directory
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create mock data files
    trivy_file = results_dir / f"trivy_results_mock_{timestamp}.json"
    grype_file = results_dir / f"grype_results_mock_{timestamp}.json"
    clair_file = results_dir / f"clair_results_mock_{timestamp}.json"
    
    # Write mock data
    with open(trivy_file, 'w') as f:
        json.dump(create_mock_trivy_data(), f, indent=2)
    print(f"✅ Created mock Trivy data: {trivy_file}")
    
    with open(grype_file, 'w') as f:
        json.dump(create_mock_grype_data(), f, indent=2)
    print(f"✅ Created mock Grype data: {grype_file}")
    
    with open(clair_file, 'w') as f:
        json.dump(create_mock_clair_data(), f, indent=2)
    print(f"✅ Created mock Clair data: {clair_file}")
    
    # Import and use the scanner to generate report
    from scan_docker import DockerVulnerabilityScanner
    
    scanner = DockerVulnerabilityScanner("mock-test-app")
    report_file = scanner.generate_combined_report(trivy_file, grype_file, clair_file)
    
    print(f"\n🎉 Mock report generated: {report_file}")
    print("📊 This shows how all three scanners look with vulnerabilities!")
    
    # Try to open the report
    import webbrowser
    try:
        webbrowser.open(f"file://{report_file.absolute()}")
        print("🌐 Report opened in browser")
    except Exception as e:
        print(f"ℹ️ Could not auto-open browser: {e}")

if __name__ == "__main__":
    main()
