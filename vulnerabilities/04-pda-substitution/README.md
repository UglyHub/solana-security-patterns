# Vulnerability 04: PDA Substitution

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Medium |
| **Common in** | Vault systems, Escrow programs, Token programs |
| **Also Known As** | PDA Verification Bypass, Seed Manipulation |

## Description

PDA (Program Derived Address) substitution occurs when a program fails to verify that a PDA was derived using the expected seeds. Attackers can create their own PDAs with different seeds and substitute them for legitimate accounts.

### What is a PDA?

A PDA is an address derived deterministically from:
1. A set of **seeds** (arbitrary bytes)
2. A **program ID**
```rust
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],  // Seeds
    &program_id                          // Program ID
);
```

The same seeds + program ID ALWAYS produce the same PDA. This makes PDAs perfect for:
- User-specific accounts (seed = user pubkey)
- Global singletons (seed = constant string)
- Escrow accounts (seed = parties involved)

### The Core Problem

If your program doesn't verify the PDA seeds, an attacker can:
1. Create a PDA with DIFFERENT seeds (that they control)
2. Pass that PDA where your expected PDA should be
3. Bypass authorization because they control the fake PDA

## The Attack Scenario

### Setup
1. Protocol creates vault PDAs using seeds: `["vault", user_pubkey]`
2. Each user has exactly ONE vault derived from their pubkey
3. User Alice has vault at PDA derived from `["vault", alice_pubkey]`

### The Exploit
```
Step 1: Attacker creates their OWN vault using their pubkey:
        PDA = derive(["vault", attacker_pubkey])
        This vault has attacker as authority

Step 2: Attacker deposits funds into protocol (gets recorded somewhere)

Step 3: Attacker calls withdraw with:
        - vault: attacker's PDA (NOT Alice's!)
        - authority: attacker's pubkey
        
        BUT targets Alice's recorded deposit somehow

Step 4: Vulnerable program:
        - Checks: is authority the vault's authority? ✓
        - DOESN'T check: is this the CORRECT vault for this operation?
        
Step 5: Program processes withdrawal incorrectly

OR (simpler attack):

Step 1: Program has global config at PDA ["config"]
Step 2: Attacker creates fake config at PDA ["config", "fake"]
Step 3: Attacker passes fake config where real config expected
Step 4: Program reads attacker-controlled config values!
```

### Why It Works

The program verified the PDA is valid (owned by program, correct type) but didn't verify it was derived from the EXPECTED seeds for this specific operation.

## Code Examples

### Anchor Framework

#### ❌ VULNERABLE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// ❌ VULNERABLE: No seeds verification!
    /// Any PDA owned by this program is accepted
    #[account(
        mut,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    /// CHECK: destination
    pub destination: UncheckedAccount<'info>,
}

pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    // ❌ We verified authority matches vault.authority
    // But we DIDN'T verify this is the correct vault for this user!
    
    // Attacker can pass ANY vault they control
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;
    // ... transfer ...
    Ok(())
}
```

#### ✅ SECURE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// ✅ SECURE: Seeds constraint verifies PDA derivation
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    /// CHECK: destination
    pub destination: UncheckedAccount<'info>,
}

pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    // ✅ Anchor verified:
    // 1. PDA = derive(["vault", authority.key()], program_id)
    // 2. Vault account address == expected PDA
    // 3. authority == vault.authority
    
    // Attacker CANNOT substitute a different vault!
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;
    // ... transfer ...
    Ok(())
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // Check signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Check owner
    if !vault.is_owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // Read vault authority
    let data = vault.try_borrow_data()?;
    let vault_authority = read_pubkey(&data, AUTHORITY_OFFSET);
    
    // ❌ VULNERABLE: Only checking authority matches
    // NOT checking this is the correct PDA!
    if authority.key() != &vault_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Attacker can pass any vault where they're the authority!
    Ok(())
}
```

#### ✅ SECURE Code
```rust
pub fn withdraw_secure(accounts: &[AccountInfo], amount: u64, bump: u8) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ SECURITY: Verify PDA derivation
    let seeds = &[b"vault".as_ref(), authority.key().as_ref(), &[bump]];
    let expected_pda = Pubkey::create_program_address(seeds, &crate::ID)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    
    // ✅ Check vault address matches expected PDA
    if vault.key() != &expected_pda {
        msg!("Invalid PDA - seeds don't match");
        return Err(ProgramError::InvalidSeeds);
    }
    
    // Now we know this is THE vault for this authority
    // Not some other vault the attacker controls
    Ok(())
}
```

## Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Vulnerable Pattern** | No `seeds` constraint | No PDA verification |
| **Secure Pattern** | `seeds = [...]` + `bump` | `create_program_address()` + compare |
| **Verification** | Automatic with constraint | Manual derivation and comparison |
| **Bump Handling** | `bump` constraint | Must pass bump as parameter |

## PDA Derivation Deep Dive

### How find_program_address Works
```rust
// Finds a valid PDA by trying bump values from 255 down to 0
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.as_ref()],
    &program_id
);

// Internally does:
for bump in (0..=255).rev() {
    let seeds_with_bump = [b"vault", user.as_ref(), &[bump]];
    if let Ok(pda) = create_program_address(&seeds_with_bump, &program_id) {
        return (pda, bump);  // Found valid PDA
    }
}
```

### How create_program_address Works
```rust
// Creates PDA from exact seeds (including bump)
// Returns error if result is on the ed25519 curve (invalid PDA)
let pda = Pubkey::create_program_address(
    &[b"vault", user.as_ref(), &[bump]],
    &program_id
)?;
```

### Why Store the Bump?

Finding the bump is expensive (~10k compute units). Storing it in the account and passing it saves compute:
```rust
// EXPENSIVE - searches for bump
let (expected_pda, _bump) = Pubkey::find_program_address(seeds, program_id);

// CHEAP - uses known bump
let expected_pda = Pubkey::create_program_address(seeds_with_bump, program_id)?;
```

## Prevention Checklist

- [ ] Every PDA account must have its seeds verified
- [ ] In Anchor: Use `seeds = [...]` and `bump` constraints
- [ ] In Pinocchio: Derive expected PDA and compare to actual address
- [ ] Store bump in account to save compute
- [ ] Include user-specific data in seeds when PDA should be user-specific
- [ ] Document expected seeds for each PDA type

## Common PDA Patterns

### User-Specific Vault
```rust
seeds = [b"vault", user.key().as_ref()]
// Each user gets exactly one vault
```

### Global Config
```rust
seeds = [b"config"]
// One config for entire program
```

### Escrow Between Two Parties
```rust
seeds = [b"escrow", party_a.key().as_ref(), party_b.key().as_ref()]
// Unique escrow for each pair
```

### Pool + User Position
```rust
// Pool
seeds = [b"pool", pool_id.as_ref()]
// User position in pool
seeds = [b"position", pool.key().as_ref(), user.key().as_ref()]
```

## References

- [Solana Cookbook: PDAs](https://solanacookbook.com/core-concepts/pdas.html)
- [Anchor PDA Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Sealevel Attacks: PDA Verification](https://github.com/coral-xyz/sealevel-attacks)