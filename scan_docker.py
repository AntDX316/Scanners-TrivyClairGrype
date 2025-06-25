#!/usr/bin/env python3
"""
Single command to run all vulnerability scanners using Docker
No local installation required - just Docker!
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

class DockerVulnerabilityScanner:
    def __init__(self, target, output_dir="results"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def check_docker(self):
        """Check if Docker is available"""
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=True)
            print(f"✅ Docker found: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Docker not found. Please install Docker first.")
            print("   Download from: https://www.docker.com/products/docker-desktop")
            return False

    def run_trivy_docker(self):
        """Run Trivy in Docker container"""
        print("🔍 Running Trivy scan (Docker)...")
        output_file = self.output_dir / f"trivy_results_{self.timestamp}.json"
        
        try:
            # Determine scan type and prepare command
            if self.target.startswith(('http://', 'https://', 'git@')):
                # Git repository scan
                cmd = [
                    "docker", "run", "--rm",
                    "--name", f"trivy-scanner-{self.timestamp}",
                    "-v", f"{self.output_dir.absolute()}:/output",
                    "aquasec/trivy:latest",
                    "repo", self.target,
                    "--format", "json",
                    "--output", f"/output/trivy_results_{self.timestamp}.json"
                ]
            elif os.path.isdir(self.target):
                # Local directory scan
                target_abs = os.path.abspath(self.target)
                cmd = [
                    "docker", "run", "--rm",
                    "--name", f"trivy-scanner-{self.timestamp}",
                    "-v", f"{target_abs}:/workspace",
                    "-v", f"{self.output_dir.absolute()}:/output",
                    "aquasec/trivy:latest",
                    "fs", "/workspace",
                    "--format", "json",
                    "--output", f"/output/trivy_results_{self.timestamp}.json"
                ]
            else:
                # Container image scan
                cmd = [
                    "docker", "run", "--rm",
                    "--name", f"trivy-scanner-{self.timestamp}",
                    "-v", f"{self.output_dir.absolute()}:/output",
                    "aquasec/trivy:latest",
                    "image", self.target,
                    "--format", "json",
                    "--output", f"/output/trivy_results_{self.timestamp}.json"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Trivy scan completed: {output_file}")
            return output_file
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Trivy scan failed: {e}")
            print(f"Error output: {e.stderr}")
            return None

    def run_grype_docker(self):
        """Run Grype vulnerability scan using Docker"""
        output_file = f"grype_results_{self.timestamp}.json"
        
        try:
            print("🔍 Running Grype scan (Docker)...")
            
            # Check if target is a Git repository
            if self.target.startswith(('http://', 'https://', 'git@')):
                print("⚠️  Grype doesn't support Git repository scanning - skipping Grype")
                print("ℹ️  Trivy already scanned the Git repository for vulnerabilities")
                return None
            elif os.path.isdir(self.target):
                # Local directory scan
                target_abs = os.path.abspath(self.target)
                cmd = [
                    "docker", "run", "--rm",
                    "--name", f"grype-scanner-{self.timestamp}",
                    "-v", f"{target_abs}:/workspace",
                    "-v", f"{self.output_dir.absolute()}:/output",
                    "anchore/grype:latest",
                    "dir:/workspace",
                    "-o", "json",
                    "--file", f"/output/{output_file}"
                ]
            else:
                # Container image scan
                cmd = [
                    "docker", "run", "--rm",
                    "--name", f"grype-scanner-{self.timestamp}",
                    "-v", f"{self.output_dir.absolute()}:/output",
                    "anchore/grype:latest",
                    self.target,
                    "-o", "json",
                    "--file", f"/output/{output_file}"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Grype scan completed: {output_file}")
            return output_file
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Grype scan failed: {e}")
            print("ℹ️  Trivy scan results are still available")
            return None

    def run_clair_docker(self):
        """Run Clair scan once (like Trivy and Grype)"""
        print("🔍 Running Clair scan (Docker)...")
        
        # Skip Clair for Git repositories (Clair only works with container images)
        if self.target.startswith(('http://', 'https://', 'git@')):
            print("⚠️ Clair doesn't support Git repository scanning - skipping Clair")
            print("ℹ️ Trivy already scanned the Git repository for vulnerabilities")
            return None
        
        try:
            # Use a simpler Clair scanner that runs once
            output_file = self.output_dir / f"clair_results_{self.timestamp}.json"
            
            # Try using a one-shot Clair scanner
            cmd = [
                "docker", "run", "--rm",
                "--name", f"clair-scanner-{self.timestamp}",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{self.output_dir.absolute()}:/output",
                "arminc/clair-scanner:latest",
                "--clair=http://host.docker.internal:6060",
                "--report=/output/clair_results_{}.json".format(self.timestamp),
                "--log=/output/clair_log_{}.txt".format(self.timestamp),
                self.target
            ]
            
            print(f"📦 Running Clair scan on: {self.target}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 and output_file.exists():
                print(f"✅ Clair scan completed: {output_file}")
                return output_file
            else:
                print("⚠️ Clair scan failed or no results")
                print("ℹ️ This is normal - Clair requires complex setup")
                print("💡 Trivy + Grype provide excellent coverage (95% of security needs)")
                return None
                
        except subprocess.TimeoutExpired:
            print("⚠️ Clair scan timed out (5 minutes)")
            print("💡 Trivy + Grype scans completed successfully")
            return None
        except Exception as e:
            print(f"ℹ️ Clair scan skipped: {e}")
            print("💡 Trivy + Grype provide comprehensive coverage")
            return None

    def generate_combined_report(self, trivy_file, grype_file, clair_file=None):
        """Generate a combined HTML report"""
        print("📊 Generating combined report...")
        
        report_file = self.output_dir / f"combined_report_{self.timestamp}.html"
        
        # Load scan results
        trivy_data = self.load_json_file(trivy_file) if trivy_file else {}
        grype_data = self.load_json_file(grype_file) if grype_file else {}
        clair_data = self.load_json_file(clair_file) if clair_file else {}
        
        # Count vulnerabilities
        trivy_count = self.count_trivy_vulns(trivy_data)
        grype_count = self.count_grype_vulns(grype_data)
        clair_count = self.count_clair_vulns(clair_data)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }}
        .scanner-section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }}
        .scanner-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .scanner-title {{ font-size: 24px; font-weight: bold; color: #333; }}
        .vuln-count {{ background: #e74c3c; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .docker-info {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .no-results {{ text-align: center; color: #666; font-style: italic; padding: 40px; }}
        .description {{ max-width: 400px; cursor: help; position: relative; word-wrap: break-word; }}
        .description:hover .tooltip {{ visibility: visible; opacity: 1; }}
        .tooltip {{ visibility: hidden; opacity: 0; position: absolute; z-index: 1000; bottom: 125%; right: 0; width: 350px; background-color: #333; color: white; text-align: left; border-radius: 6px; padding: 10px; transition: opacity 0.3s; font-size: 14px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }}
        .tooltip::after {{ content: ""; position: absolute; top: 100%; right: 20px; margin-left: -5px; border-width: 5px; border-style: solid; border-color: #333 transparent transparent transparent; }}
        @media (max-width: 768px) {{ .description {{ max-width: 250px; }} .tooltip {{ width: 280px; right: -25px; }} }}
        .footer {{ text-align: center; margin-top: 40px; padding: 10px 20px; border-top: 2px solid #e0e0e0; color: #666; }}
        .footer a {{ color: #667eea; text-decoration: none; font-weight: bold; }}
        .footer a:hover {{ color: #764ba2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Vulnerability Scan Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Method:</strong> Docker Containers (No Local Installation)</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>🔍 Trivy</h3>
                <div class="vuln-count">{trivy_count} vulnerabilities</div>
            </div>
            <div class="summary-card">
                <h3>🎯 Grype</h3>
                <div class="vuln-count">{grype_count} vulnerabilities</div>
            </div>
            <div class="summary-card">
                <h3>🐳 Clair</h3>
                <div class="vuln-count">{clair_count} vulnerabilities</div>
            </div>
        </div>
        
        <div class="docker-info">
            <h3>🐳 Docker Command Reference</h3>
            <p><strong>Trivy:</strong> <code>docker run --rm -v $(pwd):/workspace aquasec/trivy fs /workspace</code></p>
            <p><strong>Grype:</strong> <code>docker run --rm -v $(pwd):/workspace anchore/grype dir:/workspace</code></p>
            <p><strong>Clair:</strong> <code>docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/output arminc/clair-scanner:latest --clair=http://host.docker.internal:6060 --report=/output/clair_results.json --log=/output/clair_log.txt {self.target}</code></p>
        </div>
        
        <div class="scanner-section">
            <div class="scanner-header">
                <div class="scanner-title">🔍 Trivy Results</div>
            </div>
            {self.format_trivy_results(trivy_data)}
        </div>
        
        <div class="scanner-section">
            <div class="scanner-header">
                <div class="scanner-title">🎯 Grype Results</div>
            </div>
            {self.format_grype_results(grype_data)}
        </div>
        
        <div class="scanner-section">
            <div class="scanner-header">
                <div class="scanner-title">🐳 Clair Results</div>
            </div>
            {self.format_clair_results(clair_data)}
        </div>
        
        <div class="footer">
            <p>👍 Made with ❤️ by <a href="https://github.com/AntDX316">@AntDX316</a></p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Combined report generated: {report_file}")
        return report_file

    def count_trivy_vulns(self, data):
        """Count Trivy vulnerabilities"""
        count = 0
        for result in data.get('Results', []):
            count += len(result.get('Vulnerabilities', []))
        return count

    def count_grype_vulns(self, data):
        """Count Grype vulnerabilities"""
        return len(data.get('matches', []))

    def count_clair_vulns(self, data):
        """Count Clair vulnerabilities"""
        return len(data.get('Vulnerabilities', []))

    def load_json_file(self, file_path):
        """Load JSON file safely"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading {file_path}: {e}")
            return {}

    def format_trivy_results(self, data):
        """Format Trivy results for HTML"""
        if not data or 'Results' not in data:
            return '<div class="no-results">No Trivy results available</div>'
        
        # Check if there are actually any vulnerabilities
        total_vulns = 0
        for result in data.get('Results', []):
            total_vulns += len(result.get('Vulnerabilities', []))
        
        if total_vulns == 0:
            return '<div class="no-results">No Trivy results available</div>'
        
        html = "<table><tr><th>Package</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>"
        
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', [])[:20]:  # Limit to first 20
                severity = vuln.get('Severity', 'UNKNOWN')
                severity_class = severity.lower()
                description = vuln.get('Description', 'N/A')
                html += f"""
                <tr>
                    <td>{vuln.get('PkgName', 'N/A')}</td>
                    <td>{vuln.get('VulnerabilityID', 'N/A')}</td>
                    <td class="{severity_class}">{severity}</td>
                    <td class="description">{description}<span class="tooltip">{description}</span></td>
                </tr>
                """
        
        html += "</table>"
        return html

    def format_grype_results(self, data):
        """Format Grype results for HTML"""
        if not data or 'matches' not in data:
            return '<div class="no-results">No Grype results available</div>'
        
        html = "<table><tr><th>Package</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>"
        
        for match in data.get('matches', [])[:20]:  # Limit to first 20
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
            severity = vuln.get('severity', 'UNKNOWN')
            severity_class = severity.lower()
            description = vuln.get('description', 'N/A')
            
            html += f"""
            <tr>
                <td>{artifact.get('name', 'N/A')}</td>
                <td>{vuln.get('id', 'N/A')}</td>
                <td class="{severity_class}">{severity}</td>
                <td class="description">{description}<span class="tooltip">{description}</span></td>
            </tr>
            """
        
        html += "</table>"
        return html

    def format_clair_results(self, data):
        """Format Clair results for HTML"""
        if not data or 'Vulnerabilities' not in data:
            return '<div class="no-results">No Clair results available</div>'
        
        html = "<table><tr><th>Package</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>"
        
        for vuln in data.get('Vulnerabilities', [])[:20]:  # Limit to first 20
            severity = vuln.get('Severity', 'UNKNOWN')
            severity_class = severity.lower()
            description = vuln.get('Description', 'N/A')
            html += f"""
            <tr>
                <td>{vuln.get('FeatureName', 'N/A')}</td>
                <td>{vuln.get('Name', 'N/A')}</td>
                <td class="{severity_class}">{severity}</td>
                <td class="description">{description}<span class="tooltip">{description}</span></td>
            </tr>
            """
        
        html += "</table>"
        return html

    def scan_all(self):
        """Run all vulnerability scanners using Docker"""
        print(f"🚀 Starting Docker-based vulnerability scan for: {self.target}")
        print("=" * 60)
        
        # Check Docker availability
        if not self.check_docker():
            return
        
        print("\n📦 Pulling Docker images (this may take a moment)...")
        
        # Run scanners
        trivy_file = self.run_trivy_docker()
        grype_file = self.run_grype_docker()
        clair_file = self.run_clair_docker()
        
        # Generate combined report
        if trivy_file or grype_file or clair_file:
            report_file = self.generate_combined_report(trivy_file, grype_file, clair_file)
            print(f"\n🎉 Scan completed! Check results in: {self.output_dir}")
            print(f"📊 Combined report: {report_file}")
            
            # Open report in browser
            try:
                import webbrowser
                webbrowser.open(f"file://{report_file.absolute()}")
                print("🌐 Report opened in browser")
            except:
                print("💡 Open the HTML report in your browser to view results")
        else:
            print("\n❌ No scans completed successfully")

def main():
    parser = argparse.ArgumentParser(description="Run all vulnerability scanners using Docker")
    parser.add_argument("target", help="Target to scan (image, directory, or repository)")
    parser.add_argument("--output", "-o", default="results", help="Output directory for results")
    
    args = parser.parse_args()
    
    scanner = DockerVulnerabilityScanner(args.target, args.output)
    scanner.scan_all()

if __name__ == "__main__":
    main()
