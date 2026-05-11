# Ethox: Programmable Security for Crypto Wallets

**What is Ethox?**

Ethox is a **wallet firewall** — a security layer that sits between you and the blockchain. It catches dangerous transactions BEFORE they execute and asks: "Is this really what you want to do?"

Think: **Stripe Radar for crypto wallets.**

---

## The Problem

Today, $2-3 billion per year is lost to crypto scams:
- **Phishing attacks** that trick you into approving malicious contracts
- **Drain attacks** that empty your wallet in one transaction
- **Malicious approvals** that give contracts permission to steal your tokens forever
- **No undo button** — once you sign, it's gone

Your hardware wallet protects your keys. But it doesn't protect you from signing something you shouldn't.

**Ethox fills that gap.**

---

## The Solution

Ethox enforces **security policies** on your smart wallet (Safe):

```
You try to send 10 ETH
         ↓
Ethox policy says: "Max 1 ETH per tx"
         ↓
Ethox blocks it and says: "Use the 24-hour delay if you want to override"
         ↓
You have 24 hours to cancel OR confirm the transaction
```

**You stay in control. Ethox just enforces your rules.**

---

## Your Role

You are building this from scratch. Your job:

1. **Understand the architecture** — read ARCHITECTURE.md
2. **Work feature-by-feature** — each feature is isolated and testable
3. **Write smart contracts** — Solidity code in `/contracts/src/`
4. **Write tests** — Foundry tests in `/contracts/test/`
5. **Ship incrementally** — one feature at a time, fully tested

You are NOT:
- Writing a full UI yet (that comes in Phase 3)
- Building a token or DAO
- Optimizing for scale
- Supporting 10 blockchains

You ARE:
- Building production-grade contract code
- Understanding security deeply
- Testing thoroughly
- Documenting your decisions

---

## Project Structure

```
ethox/
├── contracts/                 # Smart contracts (Solidity + Foundry)
│   ├── src/
│   │   ├── core/             # Policies: storage, evaluation
│   │   ├── safe/             # Safe integration: Guard, Module
│   │   └── interfaces/       # Contract interfaces (future)
│   └── test/unit/            # Foundry tests
│
├── apps/
│   ├── api/                  # Backend (Fastify) — Phase 2
│   └── web/                  # Frontend (Next.js) — Phase 3
│
├── packages/
│   ├── shared/               # Shared types
│   └── sdk/                  # TypeScript SDK
│
├── docs/                     # Feature documentation
│   ├── FEATURE_1.md         # Spending threshold (DONE)
│   ├── FEATURE_2.md         # Wallet drain (NEXT)
│   └── ...
│
├── ARCHITECTURE.md           # System design & data flows
├── CONTRIBUTING.md           # How to write code & tests
├── PHASES.md                 # Feature breakdown
└── README.md                 # You are here
```

---

## The 7 Features

| Phase | Feature | What It Does | Status |
|-------|---------|-------------|--------|
| 1 | Spending Threshold | Block txs over X ETH | ✅ DONE |
| 2 | Wallet Drain | Block if tx removes >40% balance | 📋 Next |
| 3 | Unknown Contract | Warn on first interaction | 📋 Next |
| 4 | Rapid Tx Detection | Lock if 3+ txs in 60s | 📋 Next |
| 5 | Approval Monitor | Alert on unlimited approvals | 📋 Next |
| 6 | Cooldown/Delay | Hold risky txs 24h | 📋 Next |
| 7 | Guardian System | Guardian co-sign approval | 📋 Next |

---

## Daily Workflow

1. Read the **feature documentation** (e.g., docs/FEATURE_2.md)
2. Understand the **architecture** and **threat model**
3. Write the **smart contract** in `contracts/src/`
4. Write **comprehensive tests** in `contracts/test/unit/`
5. Run `forge test -vv` — all tests must pass
6. Commit with a clear message

**Rule:** Tests go with the code. Always.

---

## Quick Start

```bash
# Build
forge build

# Test (36 tests, all passing)
forge test -vv

# Watch mode
forge build --watch
```

---

## Read These First

1. **ARCHITECTURE.md** — how everything fits together
2. **docs/FEATURE_1.md** — what we already built
3. **CONTRIBUTING.md** — how to write code & tests
4. **PHASES.md** — all 7 features broken down

---

## Key Principles

✅ **Security first** — every design choice is about safety
✅ **Test everything** — contracts, edge cases, attacks
✅ **Clean code** — readable, auditable, simple
✅ **One feature at a time** — ship, test, move on
✅ **Document decisions** — why code is written this way

---

## Need Help?

- **How do policies work?** → ARCHITECTURE.md
- **How do I test?** → contracts/test/unit/ (examples)
- **Where do I write logic?** → CONTRIBUTING.md
- **What's the threat model?** → docs/FEATURE_X.md

---

Last updated: 2026-05-11
