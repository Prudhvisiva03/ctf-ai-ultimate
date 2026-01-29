# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [YOUR-EMAIL]

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Responsible Use

CTF-AI Ultimate is designed for:
- ✅ Authorized CTF competitions
- ✅ Educational purposes
- ✅ Cybersecurity research in controlled environments
- ✅ Authorized penetration testing

**Do NOT use for:**
- ❌ Unauthorized access to systems
- ❌ Illegal activities
- ❌ Attacking systems without permission
- ❌ Violating terms of service

## Security Best Practices

When using CTF-AI Ultimate:

1. **API Keys**: Never commit API keys to version control
2. **Network Scanning**: Only scan systems you own or have permission to test
3. **Updates**: Keep the tool updated to the latest version
4. **Isolation**: Run in isolated environments (VMs/containers) when analyzing untrusted files
5. **Logs**: Be aware that the tool creates detailed logs in the output directory

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for misuse or damage caused by this tool.
