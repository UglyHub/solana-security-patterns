# Vulnerability 01: Missing Signer Check

## 🔴 Severity: CRITICAL

## What is it?

A **missing signer check** occurs when a program fails to verify that an account has actually **signed** the transaction before allowing it to perform privileged actions.

## The Problem

In Solana, just because an account's public key is passed to an instruction doesn't mean that account authorized the action. Anyone can include any public key in a transaction - the program must verify the account actually signed.

## Real World Analogy

Imagine a bank that transfers money just by hearing someone say "I'm John Smith, transfer $1000 from my account." Without checking ID (signature), anyone could claim to be John!

## Attack Scenario

```
1. Alice creates a vault with herself as the authority
2. Alice deposits 100 SOL into the vault
3. Bob (attacker) creates a transaction:
   - Passes Alice's vault account
   - Passes Alice's public key as "authority" (but doesn't sign as Alice)
   - Passes Bob's wallet as destination
4. Program checks: "Is the authority pubkey correct?" ✅ Yes
5. Program DOESN'T check: "Did authority actually sign?" ❌ Missing!
6. Bob steals all 100 SOL
```

## Vulnerable Code

### Anchor - VULNERABLE ❌
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: Only checking pubkey, NOT signature!
    pub authority: UncheckedAccount<'info>,  // ❌ WRONG!
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // This only checks the pubkey matches, NOT that they signed!
    require!(
        ctx.accounts.vault.authority == ctx.accounts.authority.key(),
        ErrorCode::InvalidAuthority
    );
    // Attacker can pass any pubkey without signing...
}
```

### Pinocchio - VULNERABLE ❌
```rust
pub fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // Only checking pubkey matches - NOT that they signed!
    let vault_data = vault.try_borrow_data()?;
    let stored_authority = Pubkey::new(&vault_data[8..40]);
    
    if authority.key != &stored_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ MISSING: if !authority.is_signer() { return Err(...) }
    
    // Attacker steals funds here...
}
```

## Secure Code

### Anchor - SECURE ✅
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,  // ✅ CORRECT! Auto-verifies signature
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // By the time we get here, Anchor has ALREADY verified:
    // 1. authority.is_signer == true (via Signer type)
    // 2. vault.authority == authority.key() (via has_one)
    
    // Safe to proceed!
}
```

### Pinocchio - SECURE ✅
```rust
pub fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // ✅ CHECK #1: Verify they actually signed!
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ CHECK #2: Verify signer is the vault's authority
    let vault_data = vault.try_borrow_data()?;
    let stored_authority = Pubkey::new(&vault_data[8..40]);
    
    if authority.key != &stored_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Now safe to proceed!
}
```

## Key Differences

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Vulnerable | `UncheckedAccount<'info>` | No `is_signer()` call |
| Secure | `Signer<'info>` | Call `is_signer()` first |
| When checked | Account deserialization | Must be in your code |
| Error | `AccountNotSigner` | `MissingRequiredSignature` |

## Prevention Checklist

- [ ] Use `Signer<'info>` in Anchor for all authority accounts
- [ ] Always call `is_signer()` in Pinocchio before trusting authority
- [ ] Combine signature check with ownership/pubkey verification
- [ ] Never use `UncheckedAccount` for accounts that authorize actions

## Real-World Impact

Missing signer checks have led to millions in stolen funds. ANY function that:
- Withdraws funds
- Changes ownership
- Modifies critical state
- Mints/burns tokens

...MUST verify the authorizing account signed the transaction.