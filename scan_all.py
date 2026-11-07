#!/usr/bin/env python3
"""
Unified vulnerability scanner using Trivy, Clair, and Grype
"""

import os
import sys
import json
import subprocess
import argparse
from html import escape
from reporting import trivy_report, grype_report, clair_report
from datetime import datetime
from pathlib import Path

class VulnerabilityScanner:
    def __init__(self, target, output_dir="results"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    def run_trivy(self):
        """Run Trivy vulnerability scan"""
        print(" Running Trivy scan...")
        output_file = self.output_dir / f"trivy_results_{self.timestamp}.json"

        try:
            # Determine scan type based on target
            if self.target.startswith(('http://', 'https://', 'git@')):
                scan_type = "repo"
            elif os.path.isdir(self.target):
                scan_type = "fs"
            else:
                scan_type = "image"

            cmd = [
                "trivy", scan_type, self.target,
                "--scanners", "vuln,secret,misconfig",
                    "--format", "json",
                "--output", str(output_file)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f" Trivy scan completed: {output_file}")
            return output_file

        except subprocess.CalledProcessError as e:
            print(f" Trivy scan failed: {e}")
            print(f"Error output: {e.stderr}")
            return None
        except FileNotFoundError:
            print(" Trivy not found. Please install Trivy first.")
            return None

    def run_grype(self):
        """Run Grype vulnerability scan"""
        print(" Running Grype scan...")
        output_file = self.output_dir / f"grype_results_{self.timestamp}.json"

        try:
            cmd = [
                "grype", self.target,
                "-o", "json",
                "--file", str(output_file)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f" Grype scan completed: {output_file}")
            return output_file

        except subprocess.CalledProcessError as e:
            print(f" Grype scan failed: {e}")
            print(f"Error output: {e.stderr}")
            return None
        except FileNotFoundError:
            print(" Grype not found. Please install Grype first.")
            return None

    def run_clair(self):
        """Run Clair vulnerability scan (requires Clair server running)"""
        print(" Running Clair scan...")
        output_file = self.output_dir / f"clair_results_{self.timestamp}.json"

        try:
            # Check if Clair server is running
            health_check = subprocess.run(
                ["curl", "-s", "http://localhost:6060/health"],
                capture_output=True, text=True
            )

            if health_check.returncode != 0:
                print(" Clair server not running. Start with: docker run -d --name clair -p 6060:6060 quay.io/coreos/clair:latest")
                return None

            # For container images, we need to use clairctl or API calls
            # This is a simplified example - in practice you'd use clairctl
            print("  Clair integration requires additional setup with clairctl")
            print("  Skipping Clair scan for now - see documentation for full setup")
            return None

        except FileNotFoundError:
            print(" curl not found. Cannot check Clair server status.")
            return None

    def generate_combined_report(self, trivy_file, grype_file, clair_file=None):
        """Generate a combined HTML report"""
        print(" Generating combined report...")

        report_file = self.output_dir / f"combined_report_{self.timestamp}.html"

        # Load scan results
        trivy_data = self.load_json_file(trivy_file) if trivy_file else {}
        grype_data = self.load_json_file(grype_file) if grype_file else {}
        clair_data = self.load_json_file(clair_file) if clair_file else {}

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report - {escape(self.target)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .scanner-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {escape(self.target)}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="scanner-section">
        <h2>🔍 Trivy Results</h2>
        {self.format_trivy_results(trivy_data)}
    </div>

    <div class="scanner-section">
        <h2>🔍 Grype Results</h2>
        {self.format_grype_results(grype_data)}
    </div>

    <div class="scanner-section">
        <h2>🔍 Clair Results</h2>
        {self.format_clair_results(clair_data)}
    </div>
</body>
</html>
        """

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f" Combined report generated: {report_file}")
        return report_file

    def load_json_file(self, file_path):
        """Load JSON file safely"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f" Error loading {file_path}: {e}")
            return {}

    def format_trivy_results(self, data):
        return trivy_report(data)

    def format_grype_results(self, data):
        return grype_report(data)

    def format_clair_results(self, data):
        return clair_report(data)

    def scan_all(self):
        """Run all vulnerability scanners"""
        print(f" Starting vulnerability scan for: {self.target}")
        print("=" * 50)

        # Run scanners
        trivy_file = self.run_trivy()
        grype_file = self.run_grype()
        clair_file = self.run_clair()

        # Generate combined report
        if trivy_file or grype_file or clair_file:
            report_file = self.generate_combined_report(trivy_file, grype_file, clair_file)
            print(f"\n Scan completed! Check results in: {self.output_dir}")
            print(f" Combined report: {report_file}")
        else:
            print("\n No scans completed successfully")

def main():
    parser = argparse.ArgumentParser(description="Run vulnerability scans with Trivy, Clair, and Grype")
    parser.add_argument("target", help="Target to scan (image, directory, or repository)")
    parser.add_argument("--output", "-o", default="results", help="Output directory for results")

    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.target, args.output)
    scanner.scan_all()

if __name__ == "__main__":
    main()
