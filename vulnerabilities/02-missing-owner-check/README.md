# Vulnerability 02: Missing Owner Check

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Medium |
| **Common in** | Cross-program interactions, Token operations, DeFi protocols |
| **Real-World Example** | Wormhole Bridge Hack ($320M) |

## Description

A missing owner check occurs when a program fails to verify that an account is owned by the expected program before trusting its data.

### The Core Problem

In Solana, **anyone can create an account with arbitrary data**. The `owner` field on an account indicates which program has authority over that account's data. If you read data from an account without checking its owner, you might be reading attacker-controlled fake data!

### Key Insight
```
Account Owner = Which program can MODIFY this account
Account Data  = Can be ANYTHING if you control the owner
```

If an attacker owns an account, they can write whatever data they want to it. Your program will happily read that fake data unless you verify the owner first.

## The Attack Scenario

### Setup
1. A lending protocol reads user balances from "token accounts"
2. The protocol expects these accounts to be owned by the SPL Token Program
3. The protocol grants loans based on the balance it reads

### The Exploit
```
Step 1: Attacker deploys their own program (MaliciousProgram)

Step 2: Attacker creates an account owned by MaliciousProgram
        - Size: Same as a Token Account (165 bytes)
        - Data: Fake token account with 1,000,000 SOL balance

Step 3: Attacker calls the lending protocol:
        - Passes their fake account as "collateral token account"
        - Protocol reads balance: 1,000,000 SOL (FAKE!)
        - Protocol doesn't check: account.owner == TokenProgram ❌

Step 4: Protocol approves massive loan based on fake collateral

Step 5: Attacker takes loan, never repays, protocol loses everything
```

### Why It Works

The protocol only checked the DATA inside the account, not WHO OWNS the account. Since the attacker owns their fake account, they control the data completely.

## Code Examples

### Anchor Framework

#### ❌ VULNERABLE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ProcessRewardVulnerable<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// CHECK: We read data but don't verify owner!
    /// VULNERABILITY: Attacker can pass any account with fake data
    pub reward_source: UncheckedAccount<'info>,
}

pub fn process_reward_vulnerable(ctx: Context<ProcessRewardVulnerable>) -> Result<()> {
    // ❌ VULNERABLE: Reading data without owner verification!
    let data = ctx.accounts.reward_source.try_borrow_data()?;
    
    // Attacker controls this data if they own the account!
    let reward_amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    
    // Granting rewards based on potentially fake data
    ctx.accounts.user_account.balance += reward_amount;
    
    msg!("Granted {} rewards (POTENTIALLY FAKE!)", reward_amount);
    Ok(())
}
```

#### ✅ SECURE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ProcessRewardSecure<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// ✅ SECURE: Account<'info, RewardPool> verifies:
    /// 1. Owner == this program (via RewardPool::owner())
    /// 2. Discriminator matches RewardPool
    /// 3. Data deserializes correctly
    #[account(
        constraint = reward_source.authority == user.key() @ ErrorCode::InvalidAuthority
    )]
    pub reward_source: Account<'info, RewardPool>,
}

pub fn process_reward_secure(ctx: Context<ProcessRewardSecure>) -> Result<()> {
    // ✅ SAFE: Anchor verified this account is owned by our program
    // and has the correct type (RewardPool)
    let reward_amount = ctx.accounts.reward_source.pending_rewards;
    
    ctx.accounts.user_account.balance += reward_amount;
    
    msg!("✅ Granted {} verified rewards", reward_amount);
    Ok(())
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn process_reward_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    let user_account = &accounts[0];
    let reward_source = &accounts[1];
    
    // ❌ MISSING: Owner verification!
    // if !reward_source.is_owned_by(&EXPECTED_PROGRAM_ID) {
    //     return Err(ProgramError::InvalidAccountOwner);
    // }
    
    let data = reward_source.try_borrow_data()?;
    
    // ❌ DANGER: This data could be completely fake!
    let reward_amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    
    // Granting rewards based on unverified data
    Ok(())
}
```

#### ✅ SECURE Code
```rust
pub fn process_reward_secure(accounts: &[AccountInfo]) -> ProgramResult {
    let user_account = &accounts[0];
    let reward_source = &accounts[1];
    
    // ✅ SECURITY: Verify owner FIRST, before reading any data
    if !reward_source.is_owned_by(&crate::ID) {
        msg!("Error: Account not owned by this program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // Now safe to read data - we know this program controls it
    let data = reward_source.try_borrow_data()?;
    let reward_amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    
    msg!("✅ Processing {} verified rewards", reward_amount);
    Ok(())
}
```

## Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Vulnerable Pattern** | `UncheckedAccount<'info>` | No `is_owned_by()` call |
| **Secure Pattern** | `Account<'info, T>` | `if !account.is_owned_by(&id) { ... }` |
| **When Check Happens** | Automatic at deserialization | Manual in instruction logic |
| **Error on Failure** | `AccountOwnedByWrongProgram` | `ProgramError::InvalidAccountOwner` |

## Real-World Impact: Wormhole Hack

The Wormhole bridge hack ($320 million) involved a failure to properly verify account ownership:

1. Wormhole expected "guardian" accounts owned by their program
2. Attacker created fake guardian accounts with forged signatures
3. Program didn't properly verify account ownership
4. Attacker minted 120,000 wrapped ETH on Solana
5. Attacker bridged funds to Ethereum and drained liquidity

**Lesson:** Always verify account ownership before trusting account data!

## Prevention Checklist

- [ ] Every account whose data you READ must have its owner verified
- [ ] In Anchor: Use `Account<'info, T>` instead of `UncheckedAccount`
- [ ] In Pinocchio: Call `is_owned_by()` BEFORE reading any data
- [ ] For external program accounts (tokens, etc.), verify against that program's ID
- [ ] Check owner FIRST, before discriminator or any other checks
- [ ] Never trust account data without knowing who controls the account

## Common Mistakes

### Mistake 1: Checking discriminator but not owner
```rust
// ❌ WRONG: Discriminator can be faked if attacker owns account!
if data[0..8] != MY_DISCRIMINATOR {
    return Err(...);
}
// Missing owner check!
```

### Mistake 2: Checking data fields but not owner
```rust
// ❌ WRONG: All these fields can be faked!
let stored_authority = read_pubkey(&data, 8);
if stored_authority != expected_authority {
    return Err(...);
}
// Attacker just puts expected_authority in their fake account!
```

### Correct Approach
```rust
// ✅ RIGHT: Check owner FIRST
if !account.is_owned_by(&EXPECTED_PROGRAM) {
    return Err(ProgramError::InvalidAccountOwner);
}
// NOW safe to read and trust data
```

## References

- [Sealevel Attacks: Owner Checks](https://github.com/coral-xyz/sealevel-attacks/tree/main/programs/2-owner-checks)
- [Wormhole Hack Analysis](https://rekt.news/wormhole-rekt/)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)