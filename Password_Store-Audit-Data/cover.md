# Independent Security Review

## PasswordStore

**Author:** Venkatesh Pamarthi  
**GitHub:** [venkateshpamarthi](https://github.com/venkateshpamarthi)  
**Mark:** Aetherion

Independent review by Venkatesh Pamarthi. Aetherion is only a personal mark on the page — a small signature, not a firm, studio, or client engagement.

| | |
| --- | --- |
| **Protocol** | PasswordStore |
| **Review type** | Educational / portfolio review |
| **Date** | 27 September 2026 |
| **Version** | 0.1 |
| **Commit** | `2e8f81e263b3a9d18fab4fb5c46805ffc10a9990` |
| **Compiler** | Solidity 0.8.18 |
| **Chain** | Ethereum |
| **In scope** | `src/PasswordStore.sol` |

---

## Table of contents

- [About](#about)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
- [Protocol Summary](#protocol-summary)
- [Executive Summary](#executive-summary)
- [Findings](./findings.md)

---

## About

Venkatesh Pamarthi is an independent smart contract reviewer and former blockchain developer. This document is an educational portfolio review of PasswordStore. It is not a client engagement and Aetherion is only a personal mark on the page.

## Disclaimer

I made a best effort to find as many issues as I could in the time boxed for this review. I do not claim the list is complete, and I take no responsibility for how these findings are used. A security review is not an endorsement of the protocol or the product. The work here is limited to the security of the Solidity implementation in scope.

## Risk Classification

Issues are graded by impact and likelihood.

| | | **Impact** | | |
| --- | --- | :---: | :---: | :---: |
| | | High | Medium | Low |
| **Likelihood** | High | H | H/M | M |
| | Medium | H/M | M | M/L |
| | Low | M | M/L | L |

- **High impact:** assets lost, confidentiality of the stored password broken, or the owner loses control of the store.
- **Medium impact:** a subset of users or a recoverable failure of a core path.
- **Low impact:** unexpected behavior with limited or no direct loss.
- **Informational:** documentation, clarity, or best-practice notes with no runtime loss.

## Audit Details

Findings in this document correspond to commit:

```
2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
```

### Scope

```
src/
└── PasswordStore.sol
```

Out of scope: deployment scripts, tests, and dependencies except where they help prove a finding.

## Protocol Summary

PasswordStore is a single-contract application for storing and retrieving one user’s password. The design is for a single owner. Only that owner should be able to set or read the password, and others should not be able to see it.

### Roles

- **Owner:** the deployer (`msg.sender` in the constructor). Only this address should set or read the password. For this contract, only the owner should interact with it.

## Executive Summary

This review covers `PasswordStore.sol` only. It is not a paid audit.

The contract cannot keep a password secret on-chain, and `setPassword` has no owner check. Those two issues break the stated product. A missing constructor password and incorrect NatSpec are smaller.

### Issues found

| Severity | Count |
| --- | ---: |
| High | 2 |
| Medium | 0 |
| Low | 1 |
| Informational | 1 |
| Gas | 0 |
| **Total** | **4** |

| ID | Finding | Severity |
| --- | --- | --- |
| H-1 | On-chain password storage is publicly readable regardless of the `private` visibility specifier | High |
| H-2 | Missing access control on `setPassword` allows anyone to overwrite the stored password | High |
| L-1 | The constructor does not set an initial password, so the store is empty until the first `setPassword` | Low |
| I-1 | Incorrect NatSpec on `getPassword` documents a parameter the function does not accept | Informational |

Full write-ups: [findings.md](./findings.md)

---

Venkatesh Pamarthi · Aetherion
