# Vulnerability 05: Reinitialization Attack

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Easy |
| **Common in** | Account initialization, Config setup, Vault creation |
| **Also Known As** | Double Initialization, Re-init Attack |

## Description

A reinitialization attack occurs when a program allows an already-initialized account to be initialized again. This can let attackers overwrite critical data like authorities, balances, or configuration settings.

### The Core Problem

Many programs have an "initialize" function that sets up account data for the first time. If this function doesn't check whether the account was already initialized, an attacker can call it again to:

1. **Replace the authority** - Take control of someone else's account
2. **Reset balances** - Wipe out tracked deposits
3. **Change configuration** - Modify protocol parameters
4. **Corrupt state** - Break protocol invariants

### Why This Happens

Initialization typically writes to ALL fields of an account. If called twice:
- First init: Sets legitimate values
- Second init: Overwrites with attacker's values

## The Attack Scenario

### Setup
1. Alice creates a vault and deposits 100 SOL
2. Vault stores: `authority = Alice, balance = 100 SOL`
3. Initialize function doesn't check if already initialized

### The Exploit
```
Step 1: Attacker calls initialize on Alice's existing vault:
        - authority: attacker's pubkey
        - (balance resets to 0 or attacker-controlled value)

Step 2: Vault now stores:
        - authority = ATTACKER (overwritten!)
        - balance = 0 (reset!)

Step 3: Attacker is now the authority of Alice's vault

Step 4: Attacker withdraws any remaining lamports

Step 5: Alice's deposit record shows 100 SOL but vault has 0
        OR attacker controls the vault entirely
```

### Why It Works

The program never checked if the account was already initialized before overwriting all its data.

## Code Examples

### Anchor Framework

#### ❌ VULNERABLE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct InitializeVulnerable<'info> {
    /// ❌ VULNERABLE: Using `init_if_needed` without checking state!
    /// This allows reinitializing an existing account.
    #[account(
        init_if_needed,  // ❌ DANGEROUS!
        payer = authority,
        space = Vault::SIZE
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// OR even worse - manual initialization without checks:

#[derive(Accounts)]
pub struct InitializeVulnerable2<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

pub fn initialize_vulnerable(ctx: Context<InitializeVulnerable2>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ NO CHECK if already initialized!
    // Overwrites existing data
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    
    Ok(())
}
```

#### ✅ SECURE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    /// ✅ SECURE: Using `init` constraint (not `init_if_needed`)
    /// This fails if account already exists
    #[account(
        init,  // ✅ Fails if account already initialized
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

// OR with manual flag check:

pub fn initialize_with_flag(ctx: Context<InitializeManual>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ Check if already initialized
    require!(!vault.is_initialized, VaultError::AlreadyInitialized);
    
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.is_initialized = true;  // ✅ Set flag to prevent re-init
    
    Ok(())
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn initialize_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // ❌ NO CHECK if already initialized!
    // Writing directly overwrites existing data
    
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[8..40].copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, 40, 0);  // Balance = 0
    
    Ok(())
}
```

#### ✅ SECURE Code
```rust
pub fn initialize_secure(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    let data = vault.try_borrow_data()?;
    
    // ✅ Check if already initialized
    // Method 1: Check discriminator (if using discriminators)
    if data[0..8] == VAULT_DISCRIMINATOR {
        msg!("Error: Vault already initialized");
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    // Method 2: Check is_initialized flag
    // if data[INITIALIZED_OFFSET] != 0 {
    //     return Err(ProgramError::AccountAlreadyInitialized);
    // }
    
    drop(data);
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // ✅ SAFE: Account is not initialized, proceed
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[8..40].copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, 40, 0);
    data[INITIALIZED_OFFSET] = 1;  // ✅ Mark as initialized
    
    Ok(())
}
```

## Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Vulnerable Pattern** | `init_if_needed` or no check | No initialization check |
| **Secure Pattern** | `init` constraint | Check discriminator or flag first |
| **Automatic Protection** | `init` fails if exists | None - must implement manually |
| **Error on Re-init** | `AccountAlreadyInitialized` | Custom or `AccountAlreadyInitialized` |

## Methods to Prevent Reinitialization

### Method 1: Use `init` Constraint (Anchor)
```rust
#[account(init, payer = user, space = 100)]
pub account: Account<'info, MyAccount>,
```

The `init` constraint:
- Creates the account with System Program
- Fails if account already has data
- Cannot be called twice

### Method 2: Check Discriminator (Both Frameworks)
```rust
// If discriminator is set, account is initialized
if data[0..8] == MY_DISCRIMINATOR {
    return Err(ProgramError::AccountAlreadyInitialized);
}
```

Only works if:
- New accounts have zeroed data
- Discriminator is non-zero

### Method 3: Explicit `is_initialized` Flag
```rust
pub struct Vault {
    pub is_initialized: bool,  // First field
    pub authority: Pubkey,
    pub balance: u64,
}

// On init:
if vault.is_initialized {
    return Err(Error::AlreadyInitialized);
}
vault.is_initialized = true;
```

Most explicit and clear approach.

### Method 4: Use PDA with `init` (Anchor)
```rust
#[account(
    init,
    seeds = [b"vault", user.key().as_ref()],
    bump,
    payer = user,
    space = Vault::SIZE
)]
pub vault: Account<'info, Vault>,
```

PDA can only be created once with these seeds.

## When `init_if_needed` IS Safe

The `init_if_needed` constraint is safe ONLY when:
1. The account is a PDA derived from immutable data
2. Re-initialization would set the SAME values
3. You add explicit checks for critical fields
```rust
// Safe: PDA ensures one account per user, authority is always the signer
#[account(
    init_if_needed,
    seeds = [b"profile", user.key().as_ref()],
    bump,
    payer = user,
    space = Profile::SIZE
)]
pub profile: Account<'info, Profile>,
pub user: Signer<'info>,  // Authority is always the signer
```

## Prevention Checklist

- [ ] Use `init` instead of `init_if_needed` in Anchor
- [ ] Always check if account is already initialized before writing
- [ ] Use discriminators and check them before initialization
- [ ] Consider using an explicit `is_initialized` flag
- [ ] For PDAs, use seeds that guarantee uniqueness
- [ ] Never allow authority to be overwritten after initialization
- [ ] Test that calling initialize twice fails

## Real-World Impact

Reinitialization bugs have led to:
- **Authority takeover** - Attackers becoming admins
- **Fund theft** - Resetting ownership of vaults
- **Protocol manipulation** - Changing fees, parameters
- **State corruption** - Breaking protocol invariants

## References

- [Sealevel Attacks: Reinitialization](https://github.com/coral-xyz/sealevel-attacks/tree/main/programs/6-reinitialization)
- [Anchor init vs init_if_needed](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)