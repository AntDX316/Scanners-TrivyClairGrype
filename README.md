# Vulnerability Scanning with Trivy, Clair, and Grype

🚀 **One command to run all three vulnerability scanners using Docker - no local installation required!**

Scanners-TrivyClairGrype is a comprehensive, zero-installation vulnerability scanning solution that integrates three powerful security scanners (Trivy, Clair, and Grype) into a single command.

Simply run 
.\run_all.bat
 on Windows or 
./run_all.sh
 on Mac/Linux to automatically scan your codebase, Docker images, or directories for vulnerabilities, secrets, and misconfigurations using Docker containers - no local installation required.
 
 The tool generates a combined HTML report with findings from all three scanners, making it perfect for developers, DevOps teams, and security professionals who want enterprise-grade vulnerability scanning without the complexity of setting up multiple tools individually.

## 🎯 **Quick Start - Single Command**

### Windows
```batch
.\run_all.bat
```

### Mac/Linux
```bash
./run_all.sh
```

### Or directly (from within your codebase directory)
```bash
python scan_docker.py .
```

**That's it!** The script will automatically:
- ✅ Pull Docker images for all scanners
- ✅ Scan your codebase with Trivy, Grype, and Clair
- ✅ Generate a combined HTML report
- ✅ Open results in your browser
- ✅ Use descriptive container names for easy tracking

## 🏷️ **Container Names**

All containers now have **descriptive, consistent names**:

### Scanner Containers (Temporary)
- `trivy-scanner-TIMESTAMP` - Trivy vulnerability scanner
- `grype-scanner-TIMESTAMP` - Grype vulnerability scanner

### Clair Services (Persistent)
- `clair-postgres-db` - PostgreSQL database for Clair
- `clair-vulnerability-scanner` - Main Clair scanner service
- `clair-control-tool` - Clair control utility

**Easy management:**
```bash
# See what's running
docker ps

# View logs
docker logs clair-vulnerability-scanner

# Stop specific containers
docker stop trivy-scanner-20250625_070015
```

## 🔍 **What Gets Scanned**

### ✨ **Comprehensive Coverage with Trivy + Grype**

- 📁 **Source code** (vulnerabilities in dependencies)
- 🔒 **Secrets** (API keys, passwords hardcoded in code) - *Trivy only*
- 📦 **Package managers** (npm, pip, maven, gradle, composer, etc.)
- 📋 **Configuration files** (Dockerfile, Kubernetes YAML, Terraform) - *Trivy only*
- 🐳 **Container images** (OS and application vulnerabilities)
- 📊 **Software Bill of Materials (SBOM)** - *Trivy only*

### 🎯 **Scanner Comparison**

| Feature | Trivy | Grype | Clair |
|---------|-------|-------|-------|
| **Dependencies** | ✅ | ✅ | ✅ |
| **Secrets** | ✅ | ❌ | ❌ |
| **Configs** | ✅ | ❌ | ❌ |
| **Git Repos** | ✅ | ❌ | ❌ |
| **Containers** | ✅ | ✅ | ✅ |
| **Speed** | Fast | Very Fast | Consistent |
| **Setup** | Easy | Easy | Optional |

**💡 Recommendation**: Trivy + Grype provide excellent coverage for most security needs. Clair is optional for specialized container analysis.

## 📋 **Requirements**

- **Docker** (only requirement!)
- **Python 3.6+** (usually pre-installed)

### Install Docker
- **Windows/Mac**: [Docker Desktop](https://www.docker.com/products/docker-desktop)
- **Linux**: `curl -fsSL https://get.docker.com | sh`

## 🎯 **Usage Examples**

```bash
# Scan current directory (your project)
.\run_all.bat

# Scan specific directory
.\run_all.bat C:\path\to\project
./run_all.sh /path/to/project

# Scan Docker image
.\run_all.bat nginx:latest
./run_all.sh python:3.9

# Scan Git repository (real examples)
.\run_all.bat https://github.com/your-username/your-repo
```

## 📊 **What You Get**

### Automated Report Generation
- **JSON files** for each scanner in `results/` directory
- **Combined HTML report** with all findings
- **Severity-based filtering** (Critical, High, Medium, Low)
- **Package and vulnerability details**
- **Fix recommendations** when available

### Report Structure
```
results/
├── trivy_results_TIMESTAMP.json
├── grype_results_TIMESTAMP.json
├── clair_results_TIMESTAMP.json (when available)
└── combined_report_TIMESTAMP.html  ← Opens automatically
```

## 🧪 **Test with Mock Data**

Want to see how the reports look with vulnerabilities? Run the test script:

```bash
python test_with_mock_data.py
```

This generates realistic vulnerability data for all three scanners so you can see the beautiful table formatting and severity color coding in action!

## 🚀 **Alternative: Just Use Trivy (Easiest)**

If you want the **simplest solution**, just install Trivy alone - it can do 90% of what you need:

### Windows
```powershell
# Using Chocolatey
choco install trivy

# Or download directly
$version = "0.52.2"
Invoke-WebRequest -Uri "https://github.com/aquasecurity/trivy/releases/download/v$version/trivy_$($version)_Windows-64bit.zip" -OutFile "trivy.zip"
Expand-Archive trivy.zip -DestinationPath "C:\trivy"
# Add C:\trivy to PATH
```

### Mac
```bash
brew install trivy
```

### Linux
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Scan Everything with Just Trivy
```bash
# Scan your codebase for vulnerabilities and secrets
trivy fs .

# Scan container image
trivy image nginx:latest

# Scan git repository
trivy repo https://github.com/user/repo

# Scan for secrets only
trivy fs --scanners secret .

# Scan configuration files
trivy config .

# Docker version (no installation)
docker run --rm -v $(pwd):/workspace aquasec/trivy fs /workspace
```

## 🔧 **Advanced Usage**

### Individual Scanner Commands (Docker)

**Trivy:**
```bash
# Scan filesystem/codebase
docker run --rm --name trivy-scan -v $(pwd):/workspace aquasec/trivy fs /workspace

# Scan for secrets in code
docker run --rm --name trivy-secrets -v $(pwd):/workspace aquasec/trivy fs --scanners secret /workspace

# Scan container image
docker run --rm --name trivy-image aquasec/trivy image nginx:latest

# Scan git repository
docker run --rm --name trivy-repo aquasec/trivy repo https://github.com/user/repo
```

**Grype:**
```bash
# Scan directory
docker run --rm --name grype-scan -v $(pwd):/workspace anchore/grype dir:/workspace

# Scan container image
docker run --rm --name grype-image anchore/grype nginx:latest
```

**Clair:**
```bash
# Start Clair services
docker-compose up -d

# Check status
curl http://localhost:6060/health

# Stop services
docker-compose down
```

## 🛠️ **Local Installation (Alternative)**

If you prefer to install scanners locally instead of using Docker:

### Windows (PowerShell)
```powershell
# Automated installer
.\install_scanners.ps1

# Or manual
choco install trivy
# Download Grype from GitHub releases
```

### macOS
```bash
# Homebrew
brew install trivy
brew tap anchore/grype && brew install grype
```

### Linux
```bash
# Install scripts
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
```

Then use the local scanner script:
```bash
python scan_all.py .
```

## 🔍 **What Gets Detected**

### Vulnerabilities
- Known CVEs in dependencies
- Outdated packages with security issues
- OS-level vulnerabilities
- Language-specific package vulnerabilities

### Secrets & Sensitive Data
- API keys and tokens
- Database credentials
- Private keys
- Hardcoded passwords
- AWS access keys
- JWT tokens

### Misconfigurations
- Dockerfile best practices
- Kubernetes security issues
- Infrastructure as Code problems
- Insecure configurations

## 📚 **Scanner Details**

### 🔍 **Trivy** (Most Comprehensive)
- **Best for**: Complete security scanning
- **Scans**: Code, containers, configs, secrets
- **Strengths**: Most features, active development
- **Output**: Detailed CVE information

### 🎯 **Grype** (Fast & Lightweight)
- **Best for**: Quick vulnerability checks
- **Scans**: Containers, filesystems
- **Strengths**: Speed, simple output
- **Output**: Clean vulnerability list

### 🐳 **Clair** (Deep Container Analysis)
- **Best for**: Container layer analysis
- **Scans**: Container images (layer by layer)
- **Strengths**: Deep image inspection
- **Output**: Layer-specific vulnerabilities

## 🆘 **Troubleshooting**

### Docker Issues
```bash
# Check Docker is running
docker --version
docker ps

# Pull images manually if needed
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

### Permission Issues (Linux/Mac)
```bash
# Make script executable
chmod +x run_all.sh

# Run with sudo if needed
sudo ./run_all.sh
```

### Windows PowerShell Execution Policy
```powershell
# If scripts are blocked
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Container Management
```bash
# See all containers with descriptive names
docker ps -a

# Remove stopped scanner containers
docker container prune

# Stop and remove Clair services
docker-compose down -v
```

## 🌟 **Features**

- ✅ **Zero local installation** (Docker-only approach)
- ✅ **Single command execution**
- ✅ **Cross-platform** (Windows, Mac, Linux)
- ✅ **Automatic report generation**
- ✅ **Browser integration**
- ✅ **Multiple scan targets** (code, containers, repos)
- ✅ **Combined results** from all scanners
- ✅ **Professional HTML reports**
- ✅ **Descriptive container names** for easy management
- ✅ **Timestamp-based tracking**

## 🤝 **Contributing**

Feel free to submit issues and enhancement requests!

## 📚 **Additional Resources**

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype Documentation](https://github.com/anchore/grype)
- [Clair Documentation](https://quay.github.io/clair/)
- [Docker Documentation](https://docs.docker.com/)

---

**🎉 Ready to scan? Just run `.\run_all.bat` (Windows) or `./run_all.sh` (Mac/Linux)!**

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for full details.
