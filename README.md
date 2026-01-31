# Solana Security Patterns

A comprehensive educational resource demonstrating common Solana smart contract vulnerabilities and their fixes using both **Anchor** and **Pinocchio** frameworks.

## 🎯 Purpose

This repository serves as a learning resource for Solana developers to understand:
- Common vulnerability patterns in Solana programs
- How attacks exploit these vulnerabilities
- How to write secure code using proper checks
- The differences between Anchor and Pinocchio security approaches

## 📚 Vulnerabilities Covered

| # | Vulnerability | Description | Severity |
|---|---------------|-------------|----------|
| 1 | [Missing Signer Check](./vulnerabilities/01-missing-signer-check/) | Failing to verify transaction signatures | 🔴 Critical |
| 2 | [Missing Owner Check](./vulnerabilities/02-missing-owner-check/) | Not validating account ownership | 🔴 Critical |
| 3 | [Type Cosplay](./vulnerabilities/03-type-cosplay/) | Account type confusion via missing discriminator | 🔴 Critical |
| 4 | [PDA Substitution](./vulnerabilities/04-pda-substitution/) | Bypassing authority via fake PDAs | 🔴 Critical |
| 5 | [Reinitialization](./vulnerabilities/05-reinitialization/) | Resetting account state after initialization | 🟠 High |
| 6 | [Arbitrary CPI](./vulnerabilities/06-arbitrary-cpi/) | Calling untrusted programs | 🔴 Critical |
| 7 | [Integer Overflow](./vulnerabilities/07-integer-overflow/) | Arithmetic bugs leading to fund drainage | 🟠 High |

## 🔧 Frameworks

This repository demonstrates vulnerabilities in both frameworks:

### Anchor
- High-level framework with automatic safety checks
- Uses Rust's type system for security
- More beginner-friendly

### Pinocchio
- Zero-dependency, low-level framework by Anza
- Maximum control and efficiency
- Requires explicit security checks

## 📁 Repository Structure
```
solana-security-patterns/
├── README.md                          # This file
├── COMPARISON.md                      # Anchor vs Pinocchio comparison
├── vulnerabilities/
│   ├── 01-missing-signer-check/
│   │   ├── README.md                  # Vulnerability explanation
│   │   ├── anchor/
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── vulnerable.rs
│   │   │       └── secure.rs
│   │   └── pinocchio/
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs
│   │           ├── vulnerable.rs
│   │           └── secure.rs
│   ├── 02-missing-owner-check/
│   │   └── ... (same structure)
│   └── ... (7 total)
└── resources/
    ├── anchor-security-model.md
    └── pinocchio-security-model.md
```

## 🚀 Quick Start

### Prerequisites
- Rust (1.70+)
- Solana CLI (1.17+)
- Anchor CLI (0.29+) - for Anchor examples

### Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/solana-security-patterns.git
cd solana-security-patterns
```

### Explore a Vulnerability
```bash
cd vulnerabilities/01-missing-signer-check
cat README.md
```

## 📖 How to Use This Repository

1. **Start with the README** in each vulnerability folder
2. **Study the vulnerable code** to understand the flaw
3. **Review the secure code** to see the fix
4. **Compare Anchor vs Pinocchio** approaches
5. **Run tests** (where provided) to see exploits in action

## 🔑 Key Takeaways

| Anchor | Pinocchio |
|--------|-----------|
| `Signer<'info>` enforces signatures | Call `is_signer()` manually |
| `Account<'info, T>` checks owner | Call `owned_by()` manually |
| `#[account]` adds discriminator | Add discriminator field manually |
| `seeds` constraint validates PDAs | Use `find_program_address()` manually |
| `init` prevents reinitialization | Check `is_initialized` flag manually |
| `Program<'info, T>` validates CPIs | Compare program ID manually |

## 📚 Additional Resources

- [Solana Documentation](https://docs.solana.com/)
- [Anchor Book](https://book.anchor-lang.com/)
- [Pinocchio Repository](https://github.com/anza-xyz/pinocchio)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚠️ Disclaimer**: The vulnerable code in this repository is intentionally insecure for educational purposes. Never deploy vulnerable code to mainnet.