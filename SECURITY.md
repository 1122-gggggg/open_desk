# Security Policy

LatencyDesk is pre-alpha and must not be exposed as a production unattended-access service.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available. Do not open a public issue containing an exploit, secret, captured desktop data, or a working remote-control bypass.

Include:

- affected commit/version and platform;
- threat preconditions;
- minimal reproduction;
- impact on confidentiality, integrity, availability, or privilege boundary;
- suggested mitigation if known.

## Supported versions

No production version is currently supported. Security fixes target the latest `main` branch until the first tagged security-supported release.

## Security baseline

Contributions must follow `docs/THREAT_MODEL.md`. In particular, network authentication does not make messages trusted: lengths, dimensions, decompressed output, fragments, queues, and state transitions remain bounded and validated.
