# Shai-Hulud NPM Supply Chain Attack Detector

<img src="shai_hulu_detector.jpg" alt="sshd" width="80%" />

A bash script to detect indicators of compromise from the September 2025 Shai-Hulud npm supply chain attack that affected 187+ npm packages. The script currently detects 75+ confirmed compromised packages, including popular packages like `@ctrl/tinycolor` with 2 million weekly downloads.

## Overview

The Shai-Hulud attack is a sophisticated self-replicating worm that compromises npm packages through stolen maintainer credentials. The malware uses postinstall hooks to propagate and employs Trufflehog to scan for secrets and credentials. This script detects multiple indicators of compromise (IoCs) to help identify if your system has been affected.

## What it Detects

### High Risk Indicators
- **Malicious workflow files**: `shai-hulud-workflow.yml` files in `.github/workflows/`
- **Known malicious file hashes**: Files matching SHA-256 hash `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **Compromised package versions**: Specific versions of 187+ packages known to be compromised
- **Suspicious postinstall hooks**: Package.json files with postinstall scripts containing curl, wget, or eval commands
- **Trufflehog activity**: Files containing trufflehog references or credential scanning patterns
- **Shai-Hulud repositories**: Git repositories named "Shai-Hulud" (used for data exfiltration)

### Medium Risk Indicators
- **Suspicious content patterns**: References to `webhook.site` and the malicious endpoint `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Suspicious git branches**: Branches named "shai-hulud"
- **Compromised namespaces**: Packages from namespaces known to be affected (@ctrl, @crowdstrike, @art-ws, @ngx, @nativescript-community)

## Compromised Packages Detected

The script detects compromised packages from the Shai-Hulud attack, which affected 187+ packages total. **Our current detection covers 75+ confirmed compromised packages** with specific version numbers, plus broader namespace detection.

### Package Detection Method

The script loads compromised packages from an external file (`compromised-packages.txt`) which contains:
- **75+ confirmed compromised package versions** with exact version numbers
- **11 affected namespaces** for broader detection of packages from compromised maintainer accounts

### Key Compromised Packages Include
- `@ctrl/tinycolor@4.1.0, 4.1.1, 4.1.2` - Primary attack vector (2M+ weekly downloads)
- `@art-ws/*` packages (16+ packages) - Art workspace utilities
- `@crowdstrike/*` packages (25+ packages) - CrowdStrike-related packages
- `@nativescript-community/*` packages (40+ packages) - NativeScript community tools
- `ngx-bootstrap`, `angulartics2`, `koa2-swagger-ui` - Popular standalone packages

### Affected Namespaces (Complete List)
- `@ctrl/*` - Control utility packages
- `@crowdstrike/*` - CrowdStrike-related packages
- `@art-ws/*` - Art workspace packages
- `@ngx/*` - Angular-related packages
- `@nativescript-community/*` - NativeScript community packages
- `@ahmedhfarag/*`, `@operato/*`, `@teselagen/*`, `@things-factory/*`, `@hestjs/*`, `@nstudio/*` - Additional affected namespaces

### Maintaining and Updating the Package List

**Important**: The Shai-Hulud attack was self-replicating, meaning new compromised packages may still be discovered. The compromised packages list is stored in `compromised-packages.txt` for easy maintenance:

- **Format**: `package_name:version` (one per line)
- **Comments**: Lines starting with `#` are ignored
- **Updates**: The file can be updated as new compromised packages are discovered
- **Fallback**: If the file is missing, the script uses a core embedded list

### Staying Updated on New Compromised Packages

Check these security advisories regularly for newly discovered compromised packages:

- **[StepSecurity Blog](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)** - Original comprehensive analysis
- **[Semgrep Security Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)** - Detailed technical analysis
- **[JFrog Security Research](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)** - Ongoing detection of new packages
- **[Wiz Security Blog](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)** - Attack analysis with package appendix
- **[Socket.dev Blog](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)** - CrowdStrike package analysis

### How to Add Newly Discovered Packages

1. Check the security advisories above for new compromised packages
2. Add them to `compromised-packages.txt` in the format `package_name:version`
3. Test the script to ensure detection works
4. Consider contributing updates back to this repository

**Coverage Note**: While the attack affected 187+ packages total, complete enumerated lists are not always published by security firms. Our detection covers the most critical and well-documented compromised packages, plus namespace-based detection for broader coverage. This approach provides strong protection while acknowledging that the complete attack scope continues to be investigated by the security community.

## Usage

```bash
# Make the script executable
chmod +x shai-hulud-detector.sh

# Core Shai-Hulud detection (recommended for most users)
./shai-hulud-detector.sh /path/to/your/project

# Paranoid mode with additional security checks
./shai-hulud-detector.sh --paranoid /path/to/your/project

# Example scanning current directory
./shai-hulud-detector.sh .

# Show help
./shai-hulud-detector.sh --help
```

### Core vs Paranoid Mode

**Core Mode (Default)**
- Focuses specifically on Shai-Hulud attack indicators
- Recommended for most users checking for this specific threat
- Clean, focused output with minimal false positives

**Paranoid Mode (`--paranoid`)**
- Includes all core Shai-Hulud detection PLUS additional security checks
- Adds typosquatting detection and network exfiltration pattern analysis
- ⚠️ **Important**: Paranoid features are general security tools, not specific to Shai-Hulud
- May produce more false positives from legitimate code
- Useful for comprehensive security auditing

## Requirements

- macOS or Unix-like system
- Bash shell
- Standard Unix tools: `find`, `grep`, `shasum`

## Output Interpretation

### Clean System
```
✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

### Compromised System
The script will show:
- **🚨 HIGH RISK**: Definitive indicators of compromise
- **⚠️ MEDIUM RISK**: Suspicious patterns requiring manual review
- **Summary**: Count of issues found

### What to Do if Issues are Found

#### High Risk Issues
- **Immediate action required**
- Update or remove compromised packages
- Review and remove malicious workflow files
- Scan for credential theft
- Consider full system audit

#### Medium Risk Issues
- **Manual investigation needed**
- Review flagged files for legitimacy
- Check if webhook.site usage is intentional
- Verify git branch purposes

## Testing

The repository includes test cases to validate the script:

```bash
# Test on clean project (should show no issues)
./shai-hulud-detector.sh test-cases/clean-project

# Test on infected project (should show multiple issues)
./shai-hulud-detector.sh test-cases/infected-project

# Test on mixed project (should show medium risk issues)
./shai-hulud-detector.sh test-cases/mixed-project
```

## How it Works

The script performs these comprehensive checks:

1. **Package Database Loading**: Loads the complete list of 187+ compromised packages from `compromised-packages.txt`
2. **Workflow Detection**: Searches for `shai-hulud-workflow.yml` files in `.github/workflows/`
3. **Hash Verification**: Calculates SHA-256 hashes of JavaScript/JSON files against known malicious hashes
4. **Package Analysis**: Parses `package.json` files for specific compromised versions and affected namespaces
5. **Postinstall Hook Detection**: Identifies suspicious postinstall scripts that could be used for malware propagation
6. **Content Scanning**: Greps for suspicious URLs, webhook endpoints, and malicious patterns
7. **Trufflehog Activity Detection**: Looks for evidence of credential scanning tools and secret harvesting
8. **Git Analysis**: Checks for suspicious branch names and repository names
9. **Repository Detection**: Identifies "Shai-Hulud" repositories used for data exfiltration
10. **Package Integrity Checking**: Analyzes package-lock.json and yarn.lock files for compromised packages and suspicious modifications

## Limitations

- **Hash Detection**: Only detects files with the exact known malicious hash
- **Package Versions**: Detects specific compromised versions and namespace warnings, but new compromised versions may not be detected
- **False Positives**: Legitimate use of webhook.site, Trufflehog for security, or postinstall hooks will trigger alerts
- **Worm Evolution**: The self-replicating nature means new variants may emerge with different signatures
- **Coverage**: May not detect all 187+ compromised packages or future iterations of the attack
- **Package Integrity**: Relies on lockfile analysis to detect compromised packages, but sophisticated attacks may evade detection

## Contributing

If you discover additional IoCs or compromised packages related to the Shai-Hulud attack, please update the arrays in the script and test thoroughly.

## Security Note

This script is for **detection only**. It does not:
- Automatically remove malicious code
- Fix compromised packages
- Prevent future attacks

Always verify findings manually and take appropriate remediation steps.

## Latest Threat Intelligence Updates

### s1ngularity/Nx Connection (September 2025)
Recent investigations have revealed a potential connection between the Shai-Hulud campaign and the Nx package ecosystem:
- **Repository Migration Patterns**: Attackers are using repositories with "-migration" suffixes to distribute malicious packages
- **Advanced Package Integrity Checks**: Double base64-encoded `data.json` files have been discovered in compromised package versions
- **Additional Compromised Versions**: `tinycolor@4.1.1` and `tinycolor@4.1.2` have been identified as compromised
- **New Package Targets**: `angulartics2` and `koa2-swagger-ui` packages have been added to the compromised list

### Enhanced Detection Capabilities
The script now includes:
- Repository migration pattern detection
- Package-lock.json integrity verification
- Context-aware Trufflehog detection to reduce false positives
- Risk level classification (HIGH/MEDIUM/LOW) for better triage

## References

### Primary Sources
- [StepSecurity Blog: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Semgrep Security Advisory: NPM packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [Aikido: S1ngularity-nx attackers strike again](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)

### Additional Resources
- [Socket: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [Ox Security: NPM 2.0 hack: 40+ npm packages hit in major supply chain attack](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/)
- [Phoenix Security: NPM tinycolor compromise](https://phoenix.security/npm-tinycolor-compromise/)

### Attack Details
- **Initial Discovery**: September 15, 2025
- **Scale**: 187+ packages compromised
- **Attack Type**: Self-replicating worm using postinstall hooks
- **Malicious Endpoint**: `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Exfiltration Method**: GitHub repositories named "Shai-Hulud"

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
