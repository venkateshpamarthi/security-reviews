# Independent Security Review

## PuppyRaffle

**Author:** Venkatesh Pamarthi  
**GitHub:** [venkateshpamarthi](https://github.com/venkateshpamarthi)  
**Mark:** Aetherion

Independent review by Venkatesh Pamarthi. Aetherion is only a personal mark on the page — a small signature, not a firm, studio, or client engagement.

| | |
| --- | --- |
| **Protocol** | PuppyRaffle |
| **Review type** | Educational / portfolio review |
| **Date** | 9 October 2026 |
| **Version** | 0.1 |
| **Commit** | `2a47715b30cf11ca82db148704e67652ad679cd8` |
| **Compiler** | Solidity 0.7.6 |
| **Chain** | Ethereum |
| **In scope** | `src/PuppyRaffle.sol` |
| **nSLOC** | 143 |
| **Tools** | Manual review, Foundry PoCs. Aderyn was used as a helper only — it is not this report. |

---

## Table of contents

- [About](#about)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
- [Protocol Summary](#protocol-summary)
- [Executive Summary](#executive-summary)
- [Findings](./findings.md)
- [Appendix: Informational and Gas](./findings.md#appendix-informational-and-gas)

---

## About

Venkatesh Pamarthi is an independent smart contract reviewer and former blockchain developer. This document is an educational portfolio review of PuppyRaffle. It is not a client engagement and Aetherion is only a personal mark on the page.

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

- **High impact:** player or protocol ETH lost, or the raffle can no longer pay a winner or fees as designed.
- **Medium impact:** a subset of users blocked, or a core path that can be griefed but not silently drained in one shot.
- **Low impact:** unexpected behavior with limited or no direct loss.
- **Informational:** documentation, clarity, or best-practice notes with no runtime loss.

## Audit Details

Findings in this document correspond to commit:

```
2a47715b30cf11ca82db148704e67652ad679cd8
```

### Scope

```
src/
└── PuppyRaffle.sol
```

Out of scope: deployment scripts, tests, and dependencies except where they help prove a finding. `report.md` in the repo root is an Aderyn dump, not this review.

## Protocol Summary

PuppyRaffle is a single-contract raffle. Players pay an entrance fee to join an address array. Duplicates are forbidden. A player may refund their ticket. After a fixed duration, `selectWinner` sends 80% of collected ETH to a “random” winner, mints a puppy NFT, and records 20% as protocol fees for later withdrawal.

### Roles

- **Owner:** deployer. May change `feeAddress` through `changeFeeAddress`.
- **Player:** may enter through `enterRaffle` and refund through `refund`.
- **Fee recipient:** `feeAddress`, which should receive accumulated fees via `withdrawFees`.

## Executive Summary

This review covers `PuppyRaffle.sol` only. It is not a paid audit.

The most serious issues are a reentrancy on `refund` that can drain the pot, unsafe `uint64` fee accounting that wraps and bricks `withdrawFees`, and on-chain “randomness” that lets the caller of `selectWinner` bias the winner and the NFT rarity. Entry also becomes arbitrarily expensive because duplicate checks are quadratic. Informational and gas notes are in the appendix. All findings are **Open** — there is no protocol patch to mark against.

### Issues found

| Severity | Count |
| --- | ---: |
| High | 3 |
| Medium | 3 |
| Low | 1 |
| Informational | 6 |
| Gas | 2 |
| **Total** | **15** |

| ID | Finding | Severity | Status |
| --- | --- | --- | --- |
| H-1 | `refund` sends ETH before updating state, allowing reentrancy that drains the raffle | High | Open |
| H-2 | Unsafe `uint64` downcast of `fee` and overflow of `totalFees` in `selectWinner` | High | Open |
| H-3 | `selectWinner` uses weak on-chain randomness, so the caller can bias winner and rarity | High | Open |
| M-1 | Quadratic duplicate checks in `enterRaffle` can make further entries too expensive (DoS) | Medium | Open |
| M-2 | Pushing the prize to a winner without `receive`/`fallback` (or `address(0)`) can brick `selectWinner` | Medium | Open |
| M-3 | `withdrawFees` requires `balance == totalFees`, so a force-send of ETH can DoS fee withdrawal | Medium | Open |
| L-1 | `getActivePlayerIndex` returns `0` when the player is missing, which is also a valid index | Low | Open |
| I-1 | Floating, outdated Solidity pragma (`^0.7.6`) | Informational | Open |
| I-2 | `feeAddress` can be set to `address(0)` | Informational | Open |
| I-3 | `selectWinner` performs an external call before `_safeMint` (CEI) | Informational | Open |
| I-4 | Prize and fee splits use magic numbers | Informational | Open |
| I-5 | `withdrawFees` changes state without an event | Informational | Open |
| I-6 | `_isActivePlayer` is unused | Informational | Open |
| G-1 | Unchanged variables should be `constant` or `immutable` | Gas | Open |
| G-2 | Storage array `.length` is read on every loop iteration | Gas | Open |

Full write-ups: [findings.md](./findings.md)

---

Venkatesh Pamarthi · Aetherion
