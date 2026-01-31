# Anchor vs Pinocchio: Security Comparison

This document compares how Anchor and Pinocchio handle security checks, helping developers understand when to use each framework.

## Overview

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Philosophy** | Safety through abstraction | Safety through explicit control |
| **Dependencies** | Many (full SDK) | Zero external dependencies |
| **Learning Curve** | Easier | Steeper |
| **Compute Units** | Higher overhead | Minimal overhead |
| **Binary Size** | Larger | Smaller |
| **Security Checks** | Mostly automatic | All manual |

## Security Model Comparison

### 1. Signer Verification

**Anchor:**
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,  // ✅ Automatically checked
}
```
The `Signer<'info>` type **automatically** verifies that the account signed the transaction. If the account hasn't signed, the transaction fails before your instruction code runs.

**Pinocchio:**
```rust
pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // ❗ Must check manually - forgetting this is a critical vulnerability
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ... rest of logic
}
```
You must **explicitly** call `is_signer()` and handle the error. There's no compile-time safety net.

---

### 2. Owner Verification

**Anchor:**
```rust
#[derive(Accounts)]
pub struct Process<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserData>,  // ✅ Owner checked automatically
}
```
The `Account<'info, T>` type verifies:
1. The account is owned by the program (via `T::owner()`)
2. The account data deserializes correctly to type `T`
3. The discriminator matches (prevents type confusion)

**Pinocchio:**
```rust
pub fn process(accounts: &[AccountView], program_id: &Address) -> ProgramResult {
    let user_account = &accounts[0];
    
    // ❗ Must check owner manually
    if !user_account.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // ❗ Must verify discriminator manually
    let data = user_account.try_borrow()?;
    if data[0..8] != USER_DATA_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ... rest of logic
}
```

---

### 3. Account Type Discrimination

**Anchor:**
```rust
#[account]  // ✅ Automatically adds 8-byte discriminator
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]  // ✅ Different discriminator, can't be confused with Vault
pub struct UserProfile {
    pub authority: Pubkey,
    pub name: String,
}
```
The `#[account]` macro automatically:
- Generates a unique 8-byte discriminator (SHA256 hash of account name)
- Checks discriminator on deserialization
- Prevents one account type from being used as another

**Pinocchio:**
```rust
// ❗ Must define discriminators manually
pub const VAULT_DISCRIMINATOR: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
pub const USER_PROFILE_DISCRIMINATOR: [u8; 8] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

pub struct Vault {
    pub discriminator: [u8; 8],  // Must include manually
    pub authority: Address,
    pub balance: u64,
}

// ❗ Must check discriminator in every instruction
pub fn process_vault(accounts: &[AccountView]) -> ProgramResult {
    let vault = &accounts[0];
    let data = vault.try_borrow()?;
    
    if data[0..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ... rest of logic
}
```

---

### 4. PDA Validation

**Anchor:**
```rust
#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8,
        seeds = [b"vault", user.key().as_ref()],  // ✅ Seeds specified
        bump  // ✅ Bump automatically found and verified
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```
Anchor:
- Derives the PDA using the specified seeds
- Finds and stores the bump seed
- Verifies the provided account matches the derived address

**Pinocchio:**
```rust
pub fn create_vault(accounts: &[AccountView], program_id: &Address) -> ProgramResult {
    let vault = &accounts[0];
    let user = &accounts[1];
    
    // ❗ Must derive and verify PDA manually
    let (expected_pda, bump) = Address::find_program_address(
        &[b"vault", user.address().as_ref()],
        program_id
    );
    
    if vault.address() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // ... rest of logic
}
```

---

### 5. CPI Program Validation

**Anchor:**
```rust
#[derive(Accounts)]
pub struct TransferTokens<'info> {
    // ... other accounts
    pub token_program: Program<'info, Token>,  // ✅ Verified to be Token program
}
```
The `Program<'info, T>` type verifies:
1. The account's key matches `T::id()`
2. The account is executable

**Pinocchio:**
```rust
pub fn transfer_tokens(accounts: &[AccountView]) -> ProgramResult {
    let token_program = &accounts[3];
    
    // ❗ Must verify program ID manually
    if token_program.address() != &spl_token::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // Also good to check executable flag
    if !token_program.executable() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ... perform CPI
}
```

---

### 6. Initialization Protection

**Anchor:**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // ✅ Can only be called once - prevents reinitialization
        payer = user,
        space = 8 + 32 + 8
    )]
    pub vault: Account<'info, Vault>,
    // ...
}
```
The `init` constraint ensures the account:
- Has zero lamports (not yet created)
- Will be created in this instruction
- Cannot be reinitialized in future calls

**Pinocchio:**
```rust
pub struct Vault {
    pub is_initialized: bool,  // ❗ Must track manually
    pub authority: Address,
    pub balance: u64,
}

pub fn initialize(accounts: &[AccountView]) -> ProgramResult {
    let vault = &accounts[0];
    let mut data = vault.try_borrow_mut()?;
    
    // ❗ Must check initialization flag manually
    if data[8] == 1 {  // is_initialized byte
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    // Set initialized flag
    data[8] = 1;
    
    // ... rest of initialization
}
```

---

## When to Use Each Framework

### Use Anchor When:
- Building your first Solana program
- Rapid prototyping
- Team includes less experienced Solana developers
- Program complexity is high (many account types)
- IDL generation for clients is important
- Compute units are not a critical constraint

### Use Pinocchio When:
- Compute unit optimization is critical
- Binary size must be minimized
- You need maximum control over memory layout
- Building infrastructure/core protocol code
- Team is experienced with Solana internals
- You want zero external dependencies

---

## Security Checklist

### For Anchor Programs:
- [ ] Use `Signer<'info>` for accounts that must sign
- [ ] Use `Account<'info, T>` for program-owned accounts
- [ ] Use `Program<'info, T>` for CPI targets
- [ ] Use `seeds` and `bump` for PDAs
- [ ] Use `has_one` for relationship validation
- [ ] Use `constraint` for custom checks

### For Pinocchio Programs:
- [ ] Call `is_signer()` on all authority accounts
- [ ] Call `owned_by()` to verify account ownership
- [ ] Check discriminator bytes for all typed accounts
- [ ] Derive and compare PDAs using `find_program_address()`
- [ ] Track `is_initialized` flag to prevent reinitialization
- [ ] Verify program ID before any CPI
- [ ] Use `checked_*` math operations

---

## Summary

| Security Check | Anchor | Pinocchio |
|----------------|--------|-----------|
| Signer | `Signer<'info>` type | `is_signer()` method |
| Owner | `Account<'info, T>` auto-check | `owned_by()` method |
| Type/Discriminator | `#[account]` macro | Manual discriminator field |
| PDA | `seeds` + `bump` constraints | `find_program_address()` + compare |
| Reinitialization | `init` constraint | Manual `is_initialized` flag |
| CPI Target | `Program<'info, T>` type | Manual program ID comparison |
| Arithmetic | `checked_*` (recommended) | `checked_*` (required) |

**Key Insight:** Anchor provides compile-time safety through its type system, while Pinocchio requires runtime checks that the developer must remember to implement. Both can be equally secure when used correctly, but Pinocchio has more opportunities for human error.