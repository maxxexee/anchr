# Security policy

Anchr is a hackathon prototype. It is not audited and it is not ready for real legal documents, client material, or production funds.

## Supported versions

Only the `main` branch is supported. There are no maintained release branches.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

https://github.com/maxxexee/anchr/security/advisories/new

Do not open a public issue for a security problem. Do not attach real documents, decrypted material, private keys, or deployer keys to a report. Use a minimal reproduction with synthetic content.

## Scope

In scope:

- The client-side crypto in `anchr-core.js`, including key generation, AES-GCM, the Merkle tree, and the PBKDF2 key wrap
- The TOTP commitment and verification flow
- `src/AnchrAnchorRegistry.sol` and `src/AnchrVault.sol`
- The deploy scripts in `script/`
- Secrets exposure in the repository, the static bundle, or the container image
- Cross-site scripting through document names or rendered report content

Out of scope:

- Sepolia, Render, or anvil outages
- The CORS and transport configuration of the hosting platform
- Gas costs and block timestamp variance
- Reports that require a compromised browser, device, or deployer key
- Known limitations already listed in the README, including the absence of an audit

## Response

This is a small project. Reports are handled on a best effort basis. There is no service level agreement.

If the report is valid, the fix and disclosure timing will be coordinated with the reporter.
