> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# cryptocrack
![tests](https://github.com/5h4d0wn1k/cryptocrack/actions/workflows/ci.yml/badge.svg) ![MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Crypto attacks + credential cracking - hash identify+crack, rules, RSA/AES/DH attacks, cipher auto-decode, XTS-CPA

# IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

## Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

## Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

## Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

## Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

## No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

## Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## Quickstart

```bash
python3 -m pip install -e .
python3 -m cryptocrack --help
python3 -m cryptocrack demo          # offline proof demo, exit 0
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

Everything runs offline against locally crafted fixtures. Run in your own lab only.

1. `python3 -m cryptocrack demo` — asserts every stage and prints a proof JSON
   (hash vectors, crypt variants, AES FIPS-197, cracking, RSA attacks, padding
   oracle, ECB detect, CBC bitflip, CPA, DH-MITM, decoding, hygiene). Exit 0.
2. `python3 -m unittest discover -s tests` — 97 unit/black-box tests.
3. Per-attack spot checks:
   - `cryptocrack rsa wiener --e 2489 --n 11413` -> d=9
   - `cryptocrack rsa fermat --n 1022117` -> 1013 * 1009
   - `cryptocrack rsa small-e --n 3233 --e 3 --c 2744` -> plaintext 14
   - `cryptocrack crack 5f4dcc3b5aa765d61d8327deb882cf99 -a md5` -> password
   - `cryptocrack decode "Khoor Zruog" -c caesar` -> Hello World

Expected proof output: the demo JSON in `reports/demo_summary.json` (gitignored)
plus a green test suite run.

## Metrics

Measured on the live demo and test suite (see METRICS.md for the full table):

- 97/97 tests passing (stable over ~2 min runs).
- Pure-python primitives validated against known-answer vectors, openssl, and
  passlib 1.7.4: md4, md5, sha1/256/512, md5-crypt, sha256/512-crypt, AES-128/192/256.
- Full `demo` exits 0 with all stages proved (padding-oracle plaintext recovery,
  XTS CPA key recovery ~0.7 average correlation, Wiener d=9, etc.).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).
