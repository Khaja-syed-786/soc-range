# Security policy

## What this project is

SOC Simulator is a **training simulator**. Every log, user, host, IP address, domain, file hash and attack in it is
simulated: IPs come only from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
domains end in `.example`, and the lookups refuse real-looking values. It contains no real malware or attack
tooling, reads no real logs and makes no outbound network calls. (The optional, off-by-default AI Copilot talks only to an Ollama on this same PC: its address must be a loopback address or the server refuses to start.) It is meant to run on your own PC, listening on
`127.0.0.1` only, and it has no login.

Rate limiting is deliberately not implemented: the server binds to `127.0.0.1` only and is a single-user local
tool with no untrusted network exposure, so there is no network abuse for a limiter to mitigate.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/Khaja-syed-786/soc-range/security/advisories/new)**
(the repository's **Security** tab → **Report a vulnerability**). Don't open a public issue for a security problem.

Useful things to include: what an attacker could do, the version or commit, and steps to reproduce. This is a
personal project, so replies and fixes are best effort; confirmed issues are fixed in a new release and credited
in the advisory unless you'd rather not be named.

In scope: anything that lets a request from another machine, another browser tab or another user on the same PC
read or change the simulator, escape the loopback-only defaults, write outside the data folder, or run code; and
problems in the released container image or the release pipeline (signing, attestations, the published image).

Out of scope: the simulated attacks, IOCs and "malicious" events themselves (they're fake training data), and
running the app with `SOCSIM_HOST` set to a non-loopback address or with its port published without the
`127.0.0.1:` prefix, which the app and README warn against.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest release) | yes |
| anything older | no |

Only the latest release gets fixes. Each release's image is signed and has an SBOM and build provenance; see
[Verify a release](README.md#verify-a-release) to check an image before you run it.
