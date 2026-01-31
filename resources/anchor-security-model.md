# Anchor Security Model

A comprehensive guide to Anchor's built-in security features and how they protect against common vulnerabilities.

## Overview

Anchor is a framework for Solana that provides automatic security checks through its type system and macros. Understanding these protections helps you write secure code and recognize when you're bypassing them.

## Account Types and Their Protections

### `Account<'info, T>`

The most secure way to access typed accounts.

**Automatic Checks:**
- ✅ Owner verification (account.owner == T::owner())
- ✅ Discriminator verification (first 8 bytes match T's discriminator)
- ✅ Data deserialization (ensures data matches struct layout)

**Usage:**
```rust
#[account(mut)]
pub vault: Account<'info, Vault>,
```

**Vulnerabilities Prevented:**
- Missing Owner Check (Vulnerability 02)
- Type Cosplay (Vulnerability 03)

---

### `Signer<'info>`

For accounts that must sign the transaction.

**Automatic Checks:**
- ✅ is_signer == true

**Usage:**
```rust
pub authority: Signer<'info>,
```

**Vulnerabilities Prevented:**
- Missing Signer Check (Vulnerability 01)

---

### `Program<'info, T>`

For program accounts used in CPIs.

**Automatic Checks:**
- ✅ Key matches T::id()
- ✅ Account is executable

**Usage:**
```rust
pub token_program: Program<'info, Token>,
```

**Vulnerabilities Prevented:**
- Arbitrary CPI (Vulnerability 06)

---

### `UncheckedAccount<'info>` / `AccountInfo<'info>`

⚠️ **DANGEROUS** - No automatic checks!

**Automatic Checks:**
- ❌ None

**When to Use:**
- Accounts you only read pubkey/lamports from
- Accounts verified manually with constraints
- **NEVER** for accounts you deserialize or invoke

**Required:**
```rust
/// CHECK: Explain why this is safe
pub unchecked: UncheckedAccount<'info>,
```

---

## Account Constraints

### `init` Constraint

Creates a new account safely.
```rust
#[account(
    init,
    payer = user,
    space = MyAccount::SIZE
)]
pub my_account: Account<'info, MyAccount>,
```

**Protections:**
- ✅ Fails if account already exists
- ✅ Allocates exact space needed
- ✅ Sets owner to program

**Vulnerabilities Prevented:**
- Reinitialization (Vulnerability 05)

---

### `init_if_needed` Constraint

⚠️ **USE WITH CAUTION**
```rust
#[account(
    init_if_needed,
    payer = user,
    space = MyAccount::SIZE
)]
pub my_account: Account<'info, MyAccount>,
```

**Dangers:**
- Allows code to run on existing accounts
- Can overwrite existing data
- Must add manual initialization checks

**Safe Usage Pattern:**
```rust
pub fn initialize(ctx: Context<Init>) -> Result<()> {
    let account = &mut ctx.accounts.my_account;
    
    // REQUIRED: Check if already initialized
    if account.is_initialized {
        return Ok(());  // Or return error
    }
    
    // Safe to initialize
    account.is_initialized = true;
    // ...
}
```

---

### `seeds` and `bump` Constraints

Verifies PDA derivation.
```rust
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump = vault.bump
)]
pub vault: Account<'info, Vault>,
```

**Protections:**
- ✅ Verifies account address matches expected PDA
- ✅ Uses stored bump for efficiency

**Vulnerabilities Prevented:**
- PDA Substitution (Vulnerability 04)

---

### `has_one` Constraint

Verifies field matches another account.
```rust
#[account(
    has_one = authority @ MyError::InvalidAuthority
)]
pub vault: Account<'info, Vault>,
pub authority: Signer<'info>,
```

**Equivalent to:**
```rust
require!(vault.authority == authority.key(), MyError::InvalidAuthority);
```

---

### `constraint` Constraint

Custom validation logic.
```rust
#[account(
    constraint = vault.balance >= amount @ MyError::InsufficientBalance
)]
pub vault: Account<'info, Vault>,
```

---

## Discriminators

Anchor automatically generates 8-byte discriminators for each account type.

**How It Works:**
```rust
// For #[account] struct Vault
discriminator = sha256("account:Vault")[0..8]
```

**Protection:**
- Different account types have different discriminators
- `Account<T>` checks discriminator automatically
- Prevents type cosplay attacks

**Bypassed When:**
- Using `UncheckedAccount`
- Manual deserialization
- Using `try_borrow_data()` directly

---

## Common Security Patterns

### Pattern 1: Secure Withdrawal
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}
```

**Protections:**
- ✅ PDA verified (seeds + bump)
- ✅ Authority verified (Signer + has_one)
- ✅ Token program verified (Program<T>)
- ✅ Account type verified (Account<T>)

### Pattern 2: Secure Initialization
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = Vault::SIZE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}
```

**Protections:**
- ✅ Cannot reinitialize (init)
- ✅ PDA ensures uniqueness
- ✅ System program verified

---

## Security Checklist for Anchor Programs

### For Every Account:

- [ ] Use `Account<T>` for typed accounts (not `UncheckedAccount`)
- [ ] Use `Signer` for accounts that must sign
- [ ] Use `Program<T>` for CPI targets
- [ ] Add `seeds` + `bump` for PDAs
- [ ] Add `has_one` for ownership verification

### For Every Instruction:

- [ ] Use `init` for new accounts (not `init_if_needed`)
- [ ] Use checked arithmetic (`checked_add`, `checked_sub`, etc.)
- [ ] Verify all relevant constraints
- [ ] Handle errors appropriately

### Code Review Questions:

1. Is any `UncheckedAccount` actually being deserialized?
2. Are all PDAs verified with `seeds` constraint?
3. Is `init_if_needed` used? If so, is there an initialization check?
4. Are all CPIs going to verified programs?
5. Is there any unchecked arithmetic?

---

## References

- [Anchor Documentation](https://www.anchor-lang.com/docs)
- [Anchor Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Coral Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)