# Security Policy

## Supported Versions

4.x versions are supported with critical and security bug fixes.

| Version | Supported          |
| ------- | ------------------ |
| 4.3.x   | :white_check_mark: |
| 4.2.x   | :white_check_mark: |
| 4.1.x   | :white_check_mark: |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

If you believe a bug you found could have security implications,
please report it as a [Security Advisory on Github](https://github.com/zeromq/libzmq/security/advisories/new).

## Internal severity classification

We will attempt to follow this general policy when assigning a severity to
security issues. These are guidelines more than rules, and as such end
results might vary.


| Severity | Definition |
| -------- | ---------- |
| CRITICAL | endpoints using STRONG authentication are SILENTLY affected |
| HIGH | endpoints using STRONG authentication are VISIBLY affected |
| MODERATE | endpoints NOT using STRONG authentication are SILENTLY affected |
| LOW | endpoints NOT using STRONG authentication are VISIBLY affected |

STRONG authentication means transports that use cryptography, for example CURVE
and TLS.

VISIBLY affected means that platform owners are likely to immediately notice
misbehaviours, like crashes or loss of connectivity for legitimate peers.

SILENTLY affected means that without close inspection, platform owners are
unlikely to notice misbehaviours, like remote code executions or data exfiltration.
