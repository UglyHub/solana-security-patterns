# Vulnerability 06: Arbitrary CPI (Cross-Program Invocation)

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Medium-Hard |
| **Common in** | DeFi protocols, Token operations, Bridge contracts |
| **Also Known As** | CPI Target Validation, Program ID Verification |

## Description

An arbitrary CPI vulnerability occurs when a program makes a Cross-Program Invocation (CPI) to another program without verifying the target program's identity. Attackers can substitute a malicious program that mimics the expected interface but behaves differently.

### What is CPI?

Cross-Program Invocation allows one Solana program to call another. For example:
- Your program calls Token Program to transfer tokens
- Your program calls System Program to create accounts
- Your program calls a DEX to swap tokens

### The Core Problem

When making a CPI, you pass a program account that will be invoked. If you don't verify this account is the EXPECTED program, an attacker can pass their own malicious program that:

1. **Fakes success** - Returns Ok(()) without doing anything
2. **Steals funds** - Redirects transfers to attacker
3. **Manipulates state** - Returns fake data
4. **Bypasses checks** - Skips validation the real program would do

## The Attack Scenario

### Setup
1. Protocol integrates with Token Program for transfers
2. Protocol passes "token_program" account to CPI
3. Protocol doesn't verify token_program.key() == spl_token::ID

### The Exploit
```
Step 1: Attacker deploys MaliciousTokenProgram that:
        - Has same instruction interface as Token Program
        - transfer() just returns Ok(()) without moving tokens

Step 2: Attacker calls protocol's withdraw function:
        - Passes MaliciousTokenProgram as "token_program"
        - Passes their account as destination

Step 3: Protocol executes:
        - Calls "token_program".transfer(vault -> attacker, amount)
        - MaliciousTokenProgram returns Ok(())
        - Protocol thinks transfer succeeded!

Step 4: Protocol updates internal state:
        - Marks user's balance as withdrawn
        - But tokens never actually moved!

Step 5: Attacker repeats or exploits the state mismatch
```

### Why It Works

The protocol trusted any program account passed as "token_program" without verifying it's actually the Token Program.

## Code Examples

### Anchor Framework

#### ❌ VULNERABLE Code
```rust
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct TransferVulnerable<'info> {
    #[account(mut)]
    pub from: AccountInfo<'info>,
    
    #[account(mut)]
    pub to: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: ❌ Not verifying this is actually Token Program!
    pub token_program: AccountInfo<'info>,
}

pub fn transfer_vulnerable(ctx: Context<TransferVulnerable>, amount: u64) -> Result<()> {
    // ❌ VULNERABLE: Calling unverified program!
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.clone(),
        to: ctx.accounts.to.clone(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    // ❌ token_program could be ANYTHING!
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.clone(),
        cpi_accounts
    );
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

#### ✅ SECURE Code
```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, Transfer, transfer};

#[derive(Accounts)]
pub struct TransferSecure<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    /// ✅ SECURE: Program<T> verifies program ID automatically
    pub token_program: Program<'info, Token>,
}

pub fn transfer_secure(ctx: Context<TransferSecure>, amount: u64) -> Result<()> {
    // ✅ SAFE: Anchor verified token_program.key() == Token::id()
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts
    );
    
    transfer(cpi_ctx, amount)?;
    Ok(())
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn transfer_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from = &accounts[0];
    let to = &accounts[1];
    let authority = &accounts[2];
    let token_program = &accounts[3];
    
    // ❌ MISSING: Program ID verification!
    // if token_program.key() != &spl_token::ID {
    //     return Err(ProgramError::IncorrectProgramId);
    // }
    
    // ❌ VULNERABLE: Invoking unverified program!
    let ix = spl_token::instruction::transfer(
        token_program.key(),
        from.key(),
        to.key(),
        authority.key(),
        &[],
        amount,
    )?;
    
    invoke(&ix, &[from.clone(), to.clone(), authority.clone()])?;
    
    Ok(())
}
```

#### ✅ SECURE Code
```rust
pub fn transfer_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from = &accounts[0];
    let to = &accounts[1];
    let authority = &accounts[2];
    let token_program = &accounts[3];
    
    // ✅ SECURITY: Verify program ID BEFORE invoking
    if token_program.key() != &spl_token::ID {
        msg!("Error: Invalid token program");
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // ✅ SAFE: Program identity verified
    let ix = spl_token::instruction::transfer(
        token_program.key(),
        from.key(),
        to.key(),
        authority.key(),
        &[],
        amount,
    )?;
    
    invoke(&ix, &[from.clone(), to.clone(), authority.clone()])?;
    
    Ok(())
}
```

## Framework Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Vulnerable Pattern** | `AccountInfo` for programs | No program ID check |
| **Secure Pattern** | `Program<'info, T>` | `if program.key() != &EXPECTED_ID` |
| **Verification** | Automatic via type | Manual comparison |
| **Error on Mismatch** | `InvalidProgramId` | `ProgramError::IncorrectProgramId` |

## Common Programs to Verify

| Program | ID Constant | Purpose |
|---------|-------------|---------|
| System Program | `system_program::ID` | Account creation, transfers |
| Token Program | `spl_token::ID` | SPL token operations |
| Token 2022 | `spl_token_2022::ID` | Extended token features |
| Associated Token | `spl_associated_token_account::ID` | ATA creation |
| Memo Program | `spl_memo::ID` | Transaction memos |

## Types of Malicious Programs

### Type 1: No-Op Program
```rust
// Does nothing, returns success
pub fn process_instruction(...) -> ProgramResult {
    Ok(())  // Pretends to succeed
}
```
**Impact**: Operations appear to succeed but don't happen.

### Type 2: Redirect Program
```rust
// Redirects funds to attacker
pub fn process_instruction(...) -> ProgramResult {
    // Instead of transferring to intended recipient,
    // transfer to attacker's account
    transfer_to_attacker(...)?;
    Ok(())
}
```
**Impact**: Funds stolen during "legitimate" operations.

### Type 3: State Manipulation Program
```rust
// Returns fake data
pub fn process_instruction(...) -> ProgramResult {
    // Write fake balance to return account
    write_fake_balance(account, 1_000_000)?;
    Ok(())
}
```
**Impact**: Protocol makes decisions based on fake data.

## Prevention Checklist

- [ ] Verify program ID before EVERY CPI call
- [ ] In Anchor: Use `Program<'info, T>` instead of `AccountInfo`
- [ ] In Pinocchio: Compare `program.key() != &EXPECTED_ID`
- [ ] Use well-known program ID constants (not magic strings)
- [ ] Check program is executable (`is_executable()`)
- [ ] Consider using Anchor's CPI modules for type safety
- [ ] Audit all CPI calls in security reviews

## Defense in Depth

Even with program ID verification, consider:

1. **Verify account ownership**: Accounts passed to CPI should be owned by expected program
2. **Check return data**: Verify CPI results when possible
3. **Use PDAs**: PDAs signed by your program can't be controlled by others
4. **Atomic operations**: Ensure state is consistent even if CPI fails

## References

- [Solana CPI Documentation](https://docs.solana.com/developing/programming-model/calling-between-programs)
- [Anchor CPI Guide](https://www.anchor-lang.com/docs/cross-program-invocations)
- [Sealevel Attacks: CPI](https://github.com/coral-xyz/sealevel-attacks)