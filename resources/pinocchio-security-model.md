# Pinocchio Security Model

A comprehensive guide to writing secure Solana programs using Pinocchio, with manual security checks and patterns.

## Overview

Pinocchio is a lightweight, low-level framework for Solana programs. Unlike Anchor, it provides **no automatic security checks**. Every security measure must be implemented manually.

## The Golden Rule

> **In Pinocchio, if you don't check it, it's not checked.**

Every security verification must be explicit in your code.

---

## Essential Security Checks

### 1. Signer Verification

**Always verify signers before trusting their authority.**
```rust
// ✅ SECURE
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}

// ❌ VULNERABLE - No check
// Attacker can pass any pubkey as authority
```

**Vulnerabilities Prevented:**
- Missing Signer Check (Vulnerability 01)

---

### 2. Owner Verification

**Always verify account ownership before reading data.**
```rust
// ✅ SECURE
if !account.is_owned_by(&program_id) {
    return Err(ProgramError::InvalidAccountOwner);
}

// ❌ VULNERABLE - No check
// Attacker can pass account with fake data
```

**Vulnerabilities Prevented:**
- Missing Owner Check (Vulnerability 02)

---

### 3. Discriminator Verification

**Always check discriminator before deserializing.**
```rust
// Define discriminators
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT_01";
pub const USER_DISCRIMINATOR: [u8; 8] = *b"USER__01";

// ✅ SECURE
let data = account.try_borrow_data()?;
if data[0..8] != VAULT_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}

// ❌ VULNERABLE - No discriminator check
// Attacker can pass UserAccount where Vault expected
```

**Vulnerabilities Prevented:**
- Type Cosplay (Vulnerability 03)

---

### 4. PDA Verification

**Always verify PDA derivation matches expected seeds.**
```rust
// ✅ SECURE
let seeds: &[&[u8]] = &[b"vault", user.key().as_ref(), &[bump]];
let expected_pda = Pubkey::create_program_address(seeds, &program_id)?;

if account.key() != &expected_pda {
    return Err(ProgramError::InvalidSeeds);
}

// ❌ VULNERABLE - No PDA verification
// Attacker can substitute different PDA
```

**Vulnerabilities Prevented:**
- PDA Substitution (Vulnerability 04)

---

### 5. Initialization Check

**Always check if account is already initialized.**
```rust
// ✅ SECURE
let data = account.try_borrow_data()?;
if data[IS_INITIALIZED_OFFSET] != 0 {
    return Err(ProgramError::AccountAlreadyInitialized);
}

// ❌ VULNERABLE - No initialization check
// Attacker can reinitialize and overwrite data
```

**Vulnerabilities Prevented:**
- Reinitialization (Vulnerability 05)

---

### 6. Program ID Verification for CPI

**Always verify program ID before invoking.**
```rust
// ✅ SECURE
if token_program.key() != &spl_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}

invoke(&instruction, accounts)?;

// ❌ VULNERABLE - No program verification
// Attacker can substitute malicious program
```

**Vulnerabilities Prevented:**
- Arbitrary CPI (Vulnerability 06)

---

### 7. Checked Arithmetic

**Always use checked operations for arithmetic.**
```rust
// ✅ SECURE
let new_balance = balance
    .checked_sub(amount)
    .ok_or(ProgramError::InsufficientFunds)?;

let new_total = total
    .checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;

// ❌ VULNERABLE - Unchecked arithmetic
let new_balance = balance - amount;  // Can underflow!
let new_total = total + amount;      // Can overflow!
```

**Vulnerabilities Prevented:**
- Integer Overflow/Underflow (Vulnerability 07)

---

## Standard Verification Order

For every instruction, verify in this order:
```rust
pub fn process_instruction(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // 1. Parse accounts
    let account = &accounts[0];
    let authority = &accounts[1];
    
    // 2. Verify signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 3. Verify owner
    if !account.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // 4. Verify discriminator (type)
    let data = account.try_borrow_data()?;
    if data[0..8] != EXPECTED_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 5. Verify PDA (if applicable)
    let expected_pda = derive_pda(seeds, &ID)?;
    if account.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // 6. Verify field values
    let account_authority = read_pubkey(&data, AUTHORITY_OFFSET);
    if authority.key() != &account_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 7. Business logic with checked arithmetic
    let result = value.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    
    // 8. Verify CPI targets (if applicable)
    if program.key() != &expected_program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    Ok(())
}
```

---

## Account Data Layout Best Practices

### Standard Layout
```rust
/// Account Layout:
/// | Offset | Size | Field          |
/// |--------|------|----------------|
/// | 0      | 8    | discriminator  |
/// | 8      | 1    | is_initialized |
/// | 9      | 32   | authority      |
/// | 41     | 8    | balance        |
/// | 49     | 1    | bump           |

pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const IS_INITIALIZED_OFFSET: usize = 8;
pub const AUTHORITY_OFFSET: usize = 9;
pub const BALANCE_OFFSET: usize = 41;
pub const BUMP_OFFSET: usize = 49;

pub const ACCOUNT_SIZE: usize = 50;
```

### Discriminator Strategies

**Option 1: ASCII (Readable)**
```rust
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT_01";
pub const USER_DISCRIMINATOR: [u8; 8] = *b"USER__01";
```

**Option 2: Hash (Collision-resistant)**
```rust
// sha256("vault")[0..8]
pub const VAULT_DISCRIMINATOR: [u8; 8] = [0x12, 0x34, ...];
```

---

## Helper Functions

### Read Helpers
```rust
#[inline]
pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

#[inline]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[inline]
pub fn read_bool(data: &[u8], offset: usize) -> bool {
    data[offset] != 0
}
```

### Write Helpers
```rust
#[inline]
pub fn write_pubkey(data: &mut [u8], offset: usize, pubkey: &Pubkey) {
    data[offset..offset + 32].copy_from_slice(pubkey.as_ref());
}

#[inline]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[inline]
pub fn write_bool(data: &mut [u8], offset: usize, value: bool) {
    data[offset] = if value { 1 } else { 0 };
}
```

---

## Security Checklist for Pinocchio Programs

### For Every Instruction:

- [ ] Verify all required signers with `is_signer()`
- [ ] Verify account ownership with `is_owned_by()`
- [ ] Check discriminator before reading type-specific data
- [ ] Verify PDA derivation for all PDA accounts
- [ ] Check initialization status before initializing
- [ ] Verify program IDs before all CPI calls
- [ ] Use checked arithmetic for all calculations

### Before Deployment:

- [ ] Test with edge cases (0, MAX, overflow values)
- [ ] Test with malicious accounts (wrong owner, wrong type)
- [ ] Test reinitialization attempts
- [ ] Test PDA substitution attempts
- [ ] Audit all CPI calls
- [ ] Review all arithmetic operations

---

## Common Patterns

### Secure Initialization
```rust
pub fn initialize(accounts: &[AccountInfo], bump: u8) -> ProgramResult {
    let account = &accounts[0];
    let authority = &accounts[1];
    
    // 1. Verify signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 2. Verify not already initialized
    let data = account.try_borrow_data()?;
    if data[0..8] == DISCRIMINATOR || data[IS_INIT_OFFSET] != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    drop(data);
    
    // 3. Verify PDA
    let expected = Pubkey::create_program_address(
        &[b"account", authority.key().as_ref(), &[bump]],
        &ID
    )?;
    if account.key() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // 4. Initialize
    let mut data = account.try_borrow_mut_data()?;
    data[0..8].copy_from_slice(&DISCRIMINATOR);
    data[IS_INIT_OFFSET] = 1;
    write_pubkey(&mut data, AUTHORITY_OFFSET, authority.key());
    data[BUMP_OFFSET] = bump;
    
    Ok(())
}
```

### Secure Withdrawal
```rust
pub fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // 1. Verify signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 2. Verify owner
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // 3. Verify discriminator
    let data = vault.try_borrow_data()?;
    if data[0..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 4. Verify PDA
    let bump = data[BUMP_OFFSET];
    let expected = Pubkey::create_program_address(
        &[b"vault", authority.key().as_ref(), &[bump]],
        &ID
    )?;
    if vault.key() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // 5. Verify authority
    let vault_authority = read_pubkey(&data, AUTHORITY_OFFSET);
    if authority.key() != &vault_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // 6. Checked arithmetic
    let balance = read_u64(&data, BALANCE_OFFSET);
    let new_balance = balance.checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    
    drop(data);
    
    // 7. Update state
    let mut data = vault.try_borrow_mut_data()?;
    write_u64(&mut data, BALANCE_OFFSET, new_balance);
    
    // 8. Transfer lamports
    // ...
    
    Ok(())
}
```

---

## References

- [Pinocchio Documentation](https://github.com/febo/pinocchio)
- [Solana Program Security](https://docs.solana.com/developing/programming-model/security)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)