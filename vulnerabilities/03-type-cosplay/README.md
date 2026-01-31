# Vulnerability 03: Type Cosplay (Discriminator Attack)

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Medium |
| **Common in** | Programs with multiple account types, DeFi protocols |
| **Also Known As** | Account Type Confusion, Discriminator Bypass |

## Description

Type cosplay occurs when an attacker passes an account of one type where a different type is expected. If both account types have similar data layouts, the program may misinterpret the data and allow unauthorized actions.

### The Core Problem

Many Solana programs define multiple account types with similar or identical data layouts. For example:
```rust
// Vault - stores protocol funds
pub struct Vault {
    pub authority: Pubkey,  // offset 8
    pub balance: u64,       // offset 40
}

// UserProfile - stores user data  
pub struct UserProfile {
    pub owner: Pubkey,      // offset 8 - SAME POSITION!
    pub points: u64,        // offset 40 - SAME POSITION!
}
```

Without discriminator verification, an attacker can create a UserProfile (which they control) and pass it where a Vault is expected. The program reads `authority` but actually gets `owner` - which the attacker controls!

### Why Discriminators Matter

Anchor automatically adds an 8-byte discriminator (hash of the type name) to every account. This discriminator tells you WHAT TYPE the account is. But if you deserialize manually or use `UncheckedAccount`, you bypass this protection!

## The Attack Scenario

### Setup
1. Protocol has two account types: Vault and UserProfile
2. Both have a Pubkey at offset 8 and u64 at offset 40
3. Vault.authority determines who can withdraw
4. UserProfile.owner is set by the user themselves

### The Exploit
```
Step 1: Attacker creates a UserProfile with:
        - owner = attacker's pubkey (they control this!)
        - points = 1,000,000 (any value)

Step 2: Attacker calls withdraw() passing:
        - Their UserProfile as the "vault" account
        - Their pubkey as "authority"

Step 3: Vulnerable program reads bytes 8-40 as "authority"
        - Actually reading UserProfile.owner (attacker's pubkey!)
        - Check passes: authority == attacker's pubkey ✓

Step 4: Program transfers funds to attacker

Step 5: Attacker drained the protocol!
```

### Why It Works

The program never checked the discriminator (bytes 0-8) to verify the account type. It just assumed any account passed must be a Vault.

## Code Examples

### Anchor Framework

#### ❌ VULNERABLE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// CHECK: Manually reading without type verification!
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    /// CHECK: Destination
    pub destination: UncheckedAccount<'info>,
}

pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault_data = ctx.accounts.vault.try_borrow_data()?;
    
    // ❌ VULNERABLE: Skipping discriminator check!
    // Reading authority directly from offset 8
    let authority = Pubkey::try_from(&vault_data[8..40]).unwrap();
    
    // This check passes even if account is a UserProfile!
    if authority != ctx.accounts.authority.key() {
        return Err(ErrorCode::InvalidAuthority.into());
    }
    
    // ❌ DANGER: We might be reading from wrong account type!
    let balance = u64::from_le_bytes(vault_data[40..48].try_into().unwrap());
    
    // ... transfer funds ...
    Ok(())
}
```

#### ✅ SECURE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// ✅ SECURE: Account<T> verifies discriminator automatically
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    /// CHECK: Destination
    pub destination: UncheckedAccount<'info>,
}

pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    // ✅ SAFE: Anchor verified this is actually a Vault
    // The discriminator check happened during deserialization
    let vault = &ctx.accounts.vault;
    
    // This data is guaranteed to be from a real Vault
    let balance = vault.balance;
    
    // ... transfer funds ...
    Ok(())
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    let data = vault.try_borrow_data()?;
    
    // ❌ VULNERABLE: No discriminator check!
    // Attacker can pass UserProfile instead of Vault
    
    let vault_authority = read_pubkey(&data, 8);  // Actually UserProfile.owner!
    
    if authority.key() != &vault_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ DANGER: Reading wrong account type's data
    Ok(())
}
```

#### ✅ SECURE Code
```rust
pub fn withdraw_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    let data = vault.try_borrow_data()?;
    
    // ✅ SECURITY: Check discriminator FIRST
    if data[0..8] != VAULT_DISCRIMINATOR {
        msg!("Error: Account is not a Vault");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Now safe to read Vault-specific fields
    let vault_authority = read_pubkey(&data, 8);
    
    if authority.key() != &vault_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ SAFE: Verified this is actually a Vault
    Ok(())
}
```

## Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Vulnerable Pattern** | `UncheckedAccount` + manual reads | No discriminator check |
| **Secure Pattern** | `Account<'info, T>` | Check `data[0..8] == DISCRIMINATOR` |
| **Discriminator** | Auto-generated SHA256 hash | Manually defined constant |
| **When Check Happens** | Automatic at deserialization | Manual before reading data |
| **Error on Failure** | `AccountDiscriminatorMismatch` | Custom error |

## How Anchor Discriminators Work

When you use `#[account]` macro:
```rust
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
```

Anchor generates an 8-byte discriminator from:
```
sha256("account:Vault")[0..8]
```

This discriminator is:
1. Written to bytes 0-8 when account is created
2. Checked when account is loaded with `Account<'info, Vault>`
3. Unique for each account type (with extremely high probability)

## Prevention Checklist

- [ ] In Anchor: ALWAYS use `Account<'info, T>` instead of `UncheckedAccount` for accounts you read
- [ ] In Pinocchio: ALWAYS check discriminator before reading any type-specific data
- [ ] Define unique discriminators for each account type
- [ ] Check discriminator FIRST, before any other data reads
- [ ] Consider using different data layouts for different account types
- [ ] Never assume an account is a certain type without verification

## Common Account Type Confusion Patterns

### Pattern 1: Authority/Owner Confusion
```rust
// Vault: authority can withdraw
// UserProfile: owner can update
// If layouts match, attacker passes UserProfile as Vault
```

### Pattern 2: Pool/Position Confusion
```rust
// LiquidityPool: stores protocol TVL
// UserPosition: stores user's share
// Attacker passes their Position as Pool
```

### Pattern 3: Config/User Confusion
```rust
// ProtocolConfig: stores admin settings
// UserConfig: stores user preferences
// Attacker passes UserConfig as ProtocolConfig
```

## Defense in Depth

Even with discriminators, consider these additional protections:

1. **Use different field orders** for different types
2. **Add type-specific magic numbers** beyond discriminators
3. **Verify account address** if it should be a PDA with specific seeds
4. **Check account size** - different types might have different sizes

## References

- [Sealevel Attacks: Type Cosplay](https://github.com/coral-xyz/sealevel-attacks/tree/main/programs/3-type-cosplay)
- [Anchor Account Discriminators](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Cookbook: Account Data](https://solanacookbook.com/core-concepts/accounts.html)