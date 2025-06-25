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
        """Run Grype in Docker container"""
        print("🔍 Running Grype scan (Docker)...")
        output_file = self.output_dir / f"grype_results_{self.timestamp}.json"
        
        try:
            if os.path.isdir(self.target):
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
                    "--file", f"/output/grype_results_{self.timestamp}.json"
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
                    "--file", f"/output/grype_results_{self.timestamp}.json"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Grype scan completed: {output_file}")
            return output_file
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Grype scan failed: {e}")
            print(f"Error output: {e.stderr}")
            return None

    def run_clair_docker(self):
        """Start Clair with Docker Compose"""
        print("🔍 Starting Clair scan (Docker)...")
        
        try:
            # Check if docker-compose.yml exists
            if not os.path.exists("docker-compose.yml"):
                print("❌ docker-compose.yml not found. Skipping Clair scan.")
                return None
            
            # Start Clair services
            print("📦 Starting Clair services...")
            subprocess.run(["docker-compose", "up", "-d"], check=True, capture_output=True)
            
            # Wait a moment for services to start
            import time
            time.sleep(10)
            
            # Check if Clair is running
            health_check = subprocess.run(
                ["curl", "-s", "http://localhost:6060/health"],
                capture_output=True, text=True
            )
            
            if health_check.returncode == 0:
                print("✅ Clair services started successfully")
                print("ℹ️  Clair is now running at http://localhost:6060")
                print("ℹ️  Use 'docker-compose down' to stop when finished")
                return "clair_running"
            else:
                print("❌ Clair health check failed")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Clair startup failed: {e}")
            return None
        except FileNotFoundError:
            print("❌ docker-compose not found. Install Docker Compose.")
            return None

    def generate_combined_report(self, trivy_file, grype_file, clair_status=None):
        """Generate a combined HTML report"""
        print("📊 Generating combined report...")
        
        report_file = self.output_dir / f"combined_report_{self.timestamp}.html"
        
        # Load scan results
        trivy_data = self.load_json_file(trivy_file) if trivy_file else {}
        grype_data = self.load_json_file(grype_file) if grype_file else {}
        
        # Count vulnerabilities
        trivy_count = self.count_trivy_vulns(trivy_data)
        grype_count = self.count_grype_vulns(grype_data)
        
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
        .no-results {{ text-align: center; color: #666; font-style: italic; padding: 40px; }}
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
                <div class="vuln-count">{"Running" if clair_status else "Not Started"}</div>
            </div>
        </div>
        
        <div class="docker-info">
            <h3>🐳 Docker Command Reference</h3>
            <p><strong>Trivy:</strong> <code>docker run --rm -v $(pwd):/workspace aquasec/trivy fs /workspace</code></p>
            <p><strong>Grype:</strong> <code>docker run --rm -v $(pwd):/workspace anchore/grype dir:/workspace</code></p>
            <p><strong>Clair:</strong> <code>docker-compose up -d</code></p>
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
                <div class="scanner-title">🐳 Clair Status</div>
            </div>
            {self.format_clair_status(clair_status)}
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
        
        html = "<table><tr><th>Package</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>"
        
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', [])[:20]:  # Limit to first 20
                severity = vuln.get('Severity', 'UNKNOWN')
                severity_class = severity.lower()
                html += f"""
                <tr>
                    <td>{vuln.get('PkgName', 'N/A')}</td>
                    <td>{vuln.get('VulnerabilityID', 'N/A')}</td>
                    <td class="{severity_class}">{severity}</td>
                    <td>{vuln.get('Description', 'N/A')[:100]}...</td>
                </tr>
                """
        
        html += "</table>"
        return html

    def format_grype_results(self, data):
        """Format Grype results for HTML"""
        if not data or 'matches' not in data:
            return '<div class="no-results">No Grype results available</div>'
        
        html = "<table><tr><th>Package</th><th>Vulnerability</th><th>Severity</th><th>Fix Available</th></tr>"
        
        for match in data.get('matches', [])[:20]:  # Limit to first 20
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
            severity = vuln.get('severity', 'UNKNOWN')
            severity_class = severity.lower()
            
            html += f"""
            <tr>
                <td>{artifact.get('name', 'N/A')}</td>
                <td>{vuln.get('id', 'N/A')}</td>
                <td class="{severity_class}">{severity}</td>
                <td>{'Yes' if vuln.get('fix') else 'No'}</td>
            </tr>
            """
        
        html += "</table>"
        return html

    def format_clair_status(self, status):
        """Format Clair status for HTML"""
        if status:
            return """
            <div style="background: #d4edda; padding: 15px; border-radius: 5px;">
                <p>✅ Clair is running at <a href="http://localhost:6060">http://localhost:6060</a></p>
                <p>Use the Clair API or clairctl to scan container images.</p>
                <p><strong>Stop with:</strong> <code>docker-compose down</code></p>
            </div>
            """
        else:
            return """
            <div style="background: #f8d7da; padding: 15px; border-radius: 5px;">
                <p>❌ Clair not started</p>
                <p>Run <code>docker-compose up -d</code> to start Clair services.</p>
            </div>
            """

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
        clair_status = self.run_clair_docker()
        
        # Generate combined report
        if trivy_file or grype_file or clair_status:
            report_file = self.generate_combined_report(trivy_file, grype_file, clair_status)
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
