# Contributing to Anchr

Thanks for helping improve Anchr. This is a hackathon prototype, so keep the demo honest about what runs on-chain and what is only a hash.

## Ground rules

- Do not commit private keys, deployer keys, customer documents, or `.env` files.
- Keep new documentation and user-facing copy free of emojis and em dashes.
- Keep commit authorship with the repository owner. Do not add co-author or generated-by trailers.
- Open an issue before a large change so the approach can be discussed.
- Report security problems privately using [SECURITY.md](SECURITY.md), not a public issue.

## Setup

Requirements: Node.js 20 or newer, and Foundry for the contracts.

```bash
git clone https://github.com/maxxexee/anchr.git
cd anchr
git submodule update --init --recursive
npm ci
```

The site is static. Serve the repository root and open `http://localhost:8080`:

```bash
python3 -m http.server 8080
```

The browser crypto in `anchr-core.js` needs Web Crypto, so use a current browser and either `localhost` or HTTPS.

## Checks

Run these before opening a pull request:

```bash
forge fmt --check
forge build --sizes
forge test -vvv
node scripts/check-repo.mjs
```

## Contracts

`src/AnchrAnchorRegistry.sol` stores Merkle roots. Once a root is anchored it cannot be changed or removed. `src/AnchrVault.sol` stores encrypted bytes, the wrapped key, and a TOTP commitment, and exposes `shred` to delete them.

Change the contract and the frontend together. The ABI used by the pages has to match the deployed address, and the deploy scripts in `script/` pin the constructor arguments.

Run `forge fmt` before committing. CI fails on formatting drift.

## Browser crypto

`anchr-core.js` holds the whole client-side pipeline: AES-256-GCM for the document, a Merkle tree over 32-byte chunks of the ciphertext, and a PBKDF2-derived key that wraps the AES key from the TOTP secret. Plaintext must never leave the page. If you touch this file, keep the encrypt, hash, and wrap steps in separate functions so they stay testable.

## Pull requests

- Keep the change focused and describe the problem it solves.
- Update the README, docs, or screenshots when behavior changes.
- Include the commands you ran and the output that shows the change works.
- Do not include `.env`, `node_modules`, `out`, `cache`, or `broadcast` output.
- Do not add attribution trailers to commits.

## Commit messages

Use a short imperative subject, for example:

```text
Fix the anchor registry duplicate check
Add the vault seal flow
```

## License

By contributing, you agree that your contribution is licensed under the MIT License. See [LICENSE](LICENSE).
