# Security Policy & Ethical Use

## Authorized Use Only

`security-toolkit` is designed strictly for **educational purposes, authorized security assessments, defensive monitoring (Blue Team), and DevSecOps automation**.

- Only run network scans (`ports`, `ping`) or web audits (`http-audit`) against systems and networks you own or have explicit written authorization to test.
- Never paste production credentials or sensitive secrets into public CI logs or bug reports.

## Reporting a Vulnerability

If you discover a security vulnerability in this repository (including CI/CD workflows, container configuration, or Python modules):

1. Do **not** open a public issue with exploit details.
2. Report it privately using GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability**) or contact the maintainer directly.
3. Provide steps to reproduce and potential impact so the fix can be validated promptly.
