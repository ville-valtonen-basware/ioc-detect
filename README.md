# Shai-Hulud NPM Supply Chain Attack Detector

A bash script to detect indicators of compromise from the September 2025 Shai-Hulud npm supply chain attack that affected over 40 npm packages, including popular packages like `@ctrl/tinycolor` with 2 million weekly downloads.

## Overview

The Shai-Hulud attack is a sophisticated supply chain compromise that injected malicious code into numerous npm packages. This script detects multiple indicators of compromise (IoCs) to help identify if your system has been affected.

## What it Detects

### High Risk Indicators
- **Malicious workflow files**: `shai-hulud-workflow.yml` files in `.github/workflows/`
- **Known malicious file hashes**: Files matching SHA-256 hash `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **Compromised package versions**: Specific versions of 18+ packages known to be compromised

### Medium Risk Indicators
- **Suspicious content patterns**: References to `webhook.site` and the malicious endpoint `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Suspicious git branches**: Branches named "shai-hulud"

## Compromised Packages Detected

The script checks for these specific compromised package versions:

- `@ctrl/tinycolor@4.1.0`
- `@ctrl/deluge@1.2.0`
- `@nativescript-community/push@1.0.0`
- `@nativescript-community/ui-material-*@7.2.49` (multiple packages)

## Usage

```bash
# Make the script executable
chmod +x shai-hulud-detector.sh

# Scan a single project
./shai-hulud-detector.sh /path/to/your/project

# Scan your entire projects directory
./shai-hulud-detector.sh /path/to/projects

# Example scanning current directory
./shai-hulud-detector.sh .
```

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

The script performs these checks:

1. **Workflow Detection**: Searches for `shai-hulud-workflow.yml` files
2. **Hash Verification**: Calculates SHA-256 hashes of JavaScript/JSON files
3. **Package Analysis**: Parses `package.json` files for compromised versions
4. **Content Scanning**: Greps for suspicious URLs and patterns
5. **Git Analysis**: Checks for suspicious branch names

## Limitations

- **Hash Detection**: Only detects files with the exact known malicious hash
- **Package Versions**: Only detects the specific compromised versions listed
- **False Positives**: Legitimate use of webhook.site will trigger medium risk alerts
- **Coverage**: May not detect all variants or future iterations of the attack

## Contributing

If you discover additional IoCs or compromised packages related to the Shai-Hulud attack, please update the arrays in the script and test thoroughly.

## Security Note

This script is for **detection only**. It does not:
- Automatically remove malicious code
- Fix compromised packages
- Prevent future attacks

Always verify findings manually and take appropriate remediation steps.

## References

- [StepSecurity Blog: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- Attack occurred: September 15, 2025
- Malicious endpoint: `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
