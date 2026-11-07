# Vulnerability scanning with Trivy and Grype

Run dependency, secret, and configuration checks with Docker, then view a combined HTML report. Python 3.9+ and a running Docker engine are required; no Python packages are needed.

```powershell
# Windows: current directory, another directory, image, or Git repository
.\run_all.bat
.\run_all.bat C:\path\to\project --no-browser
```

```bash
# Linux/macOS
./run_all.sh /path/to/project --no-browser
python3 scan_docker.py nginx:latest --output results
python3 scan_docker.py https://github.com/your-org/your-repo
```

The launchers locate the Python script relative to themselves. Relative scan targets and output paths are resolved from the caller's working directory. Options are forwarded to the Python CLI.

## Coverage

| Target | Trivy | Grype | Legacy Clair (opt-in) |
| --- | --- | --- | --- |
| Directory | Dependencies, secrets, configuration | Dependencies | Unsupported |
| Registry image | Vulnerabilities, secrets, image configuration | Vulnerabilities | Requires configured server |
| Git repository URL | Dependencies, secrets, configuration | Skipped | Unsupported |

Trivy explicitly enables `vuln,secret,misconfig`. Coverage depends on supported package files and available vulnerability databases. Registry images must be accessible from inside the scanner containers; local-only Docker images and private-registry credentials are not wired into these containers.

## Reports and failures

Reports are written under `results/` by default:

- Per-scanner JSON files retain the scanner's original output.
- `combined_report_TIMESTAMP.html` contains every reported finding without the previous 20-row cutoff, installed and fixed package versions, configuration remediation, and secret rule/location metadata.
- HTML text is escaped. Secret matches and source snippets are omitted from the combined HTML. **Raw Trivy JSON can contain sensitive material; keep scan artifacts private.**
- Missing and failed results are labeled unavailable rather than shown as zero vulnerabilities. A completed scan with no findings has a separate message.

The Docker CLI exits with `0` when all applicable requested scanners completed, and `2` when required scanner execution failed or returned missing/invalid JSON. Findings themselves do not cause a failure exit code. Git URLs intentionally skip Grype. `--no-browser` disables automatic report opening for automation. Trivy and Grype each have a 15-minute process timeout.

Directory mounts are read-only. Output directories are writable. Scanner images currently use `latest`; image pinning and persistent database caches remain future work.

## Clair status

The existing Compose configuration and `--clair` runner use a legacy third-party Clair integration. They have **not** been migrated to modern Clair v4 or verified in this update. Clair is disabled by default; enabling it requires a separately configured compatible server and an image target:

```bash
python3 scan_docker.py nginx:latest --clair
```

The local `scan_all.py` entry point remains available for locally installed Trivy and Grype and shares the improved HTML rendering. Its execution/status behavior has not been brought to parity with the Docker entry point.

## Validation

```bash
python -m unittest -v test_reporting
python test_with_mock_data.py
```

The mock-data script demonstrates rendering; it does not verify live scanner behavior.

## Next improvements

- Normalize and deduplicate scanner findings while preserving package identity and scanner evidence.
- Add severity/fixability policies, expiring exceptions, and baseline comparisons for CI.
- Add SARIF and structured combined JSON exports.
- Pin scanner images and cache their vulnerability databases.
- Replace the legacy Clair path with a verified v4 integration.

## Documentation

[Trivy](https://trivy.dev/) · [Grype](https://oss.anchore.com/docs/) · [Clair](https://quay.github.io/clair/)

## License

See [LICENSE](LICENSE).
