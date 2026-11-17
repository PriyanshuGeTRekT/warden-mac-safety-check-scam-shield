# Security policy

## Supported versions

Only the [latest release](https://github.com/PriyanshuGeTRekT/warden-mac-safety-check-scam-shield/releases/latest) of Warden receives security fixes. Please update to it and check that the problem still happens before reporting.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Older releases | No        |

## Reporting a vulnerability

**Please do not report security problems in public issues, discussions or pull requests.**

Report them privately through GitHub:

1. Open the [Security tab](https://github.com/PriyanshuGeTRekT/warden-mac-safety-check-scam-shield/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the problem, the Warden and macOS versions affected, and the steps to reproduce it. A proof of concept helps.

You will get a reply as soon as possible, usually within a week. Once the problem is confirmed, a fix is prepared and released, and the advisory is published with credit to you unless you prefer to stay anonymous.

## Scope

Examples of what counts as a security problem in Warden:

- Warden changing any setting, file or process without the person asking (it should only read; closing a tool happens only when asked).
- Warden closing a process that is not the remote-control tool it named.
- Warden making any network request (it should make none), or exposing the Safety Check to other users.
- A way for a remote-control tool to open without Warden's shield noticing, if it is in the recognised list.

Warden is not notarized by Apple, and the "Open Anyway" step on first launch is expected. That alone is not a vulnerability.
