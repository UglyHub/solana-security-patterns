# Vulnerability 07: Integer Overflow/Underflow

## Overview

| Property | Value |
|----------|-------|
| **Severity** | 🔴 Critical |
| **Difficulty to Exploit** | Easy-Medium |
| **Common in** | Balance calculations, Fee computation, Token amounts |
| **Also Known As** | Arithmetic Overflow, Wraparound Bug |

## Description

Integer overflow/underflow occurs when arithmetic operations produce results outside the range of the integer type, causing the value to "wrap around" to an unexpected number.

### The Core Problem

In Rust, integers have fixed sizes with minimum and maximum values:

| Type | Min | Max |
|------|-----|-----|
| u8 | 0 | 255 |
| u16 | 0 | 65,535 |
| u32 | 0 | 4,294,967,295 |
| u64 | 0 | 18,446,744,073,709,551,615 |

When calculations exceed these bounds:
- **Overflow**: Value wraps from max to 0 (e.g., 255 + 1 = 0 for u8)
- **Underflow**: Value wraps from 0 to max (e.g., 0 - 1 = 255 for u8)

### Rust's Behavior

- **Debug mode**: Overflow panics (crashes)
- **Release mode**: Overflow wraps silently! ⚠️

Solana programs run in release mode, so overflows wrap silently without any error!

## The Attack Scenario

### Overflow Attack (Balance Inflation)
```
Step 1: User has balance = 100 tokens
Step 2: Protocol calculates: balance + massive_deposit
Step 3: If massive_deposit = u64::MAX - 50:
        100 + (u64::MAX - 50) = 49 (WRAPPED!)
Step 4: User's balance is now 49 instead of huge number
```

### Underflow Attack (Balance Manipulation)
```
Step 1: User has balance = 10 tokens
Step 2: User requests withdrawal of 11 tokens
Step 3: Protocol calculates: balance - withdrawal = 10 - 11
Step 4: Without underflow check: 10 - 11 = u64::MAX (18 quintillion!)
Step 5: User now has massive balance!
```

### Fee Bypass Attack
```
Step 1: Protocol charges 1% fee: amount * fee_bps / 10000
Step 2: Attacker uses amount that causes overflow in multiplication
Step 3: Result wraps to small number
Step 4: Attacker pays almost no fees!
```

## Code Examples

### Anchor/Rust Framework

#### ❌ VULNERABLE Code
```rust
pub fn withdraw_vulnerable(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ VULNERABLE: No underflow check!
    // If amount > balance, this wraps to huge number in release mode
    vault.balance = vault.balance - amount;
    
    // ❌ VULNERABLE: No overflow check!
    vault.total_withdrawn = vault.total_withdrawn + amount;
    
    Ok(())
}

pub fn calculate_fee_vulnerable(amount: u64, fee_bps: u64) -> u64 {
    // ❌ VULNERABLE: Multiplication can overflow!
    // If amount is large, amount * fee_bps overflows
    amount * fee_bps / 10000
}
```

#### ✅ SECURE Code
```rust
pub fn withdraw_secure(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SECURE: checked_sub returns None on underflow
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(VaultError::InsufficientBalance)?;
    
    // ✅ SECURE: checked_add returns None on overflow
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    
    Ok(())
}

pub fn calculate_fee_secure(amount: u64, fee_bps: u64) -> Result<u64> {
    // ✅ SECURE: Use checked operations for all arithmetic
    let numerator = amount
        .checked_mul(fee_bps)
        .ok_or(FeeError::Overflow)?;
    
    numerator
        .checked_div(10000)
        .ok_or(FeeError::DivisionByZero)
}

// ✅ ALTERNATIVE: Use u128 for intermediate calculations
pub fn calculate_fee_u128(amount: u64, fee_bps: u64) -> Result<u64> {
    let numerator = (amount as u128)
        .checked_mul(fee_bps as u128)
        .ok_or(FeeError::Overflow)?;
    
    let result = numerator / 10000u128;
    
    // Check result fits in u64
    if result > u64::MAX as u128 {
        return Err(FeeError::Overflow.into());
    }
    
    Ok(result as u64)
}
```

### Pinocchio Framework

#### ❌ VULNERABLE Code
```rust
pub fn transfer_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from_data = from.try_borrow_data()?;
    let from_balance = read_u64(&from_data, BALANCE_OFFSET);
    drop(from_data);
    
    let to_data = to.try_borrow_data()?;
    let to_balance = read_u64(&to_data, BALANCE_OFFSET);
    drop(to_data);
    
    // ❌ VULNERABLE: No underflow check!
    let new_from_balance = from_balance - amount;
    
    // ❌ VULNERABLE: No overflow check!
    let new_to_balance = to_balance + amount;
    
    // Write potentially wrapped values
    // ...
}
```

#### ✅ SECURE Code
```rust
pub fn transfer_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from_data = from.try_borrow_data()?;
    let from_balance = read_u64(&from_data, BALANCE_OFFSET);
    drop(from_data);
    
    let to_data = to.try_borrow_data()?;
    let to_balance = read_u64(&to_data, BALANCE_OFFSET);
    drop(to_data);
    
    // ✅ SECURE: Check underflow
    let new_from_balance = from_balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    
    // ✅ SECURE: Check overflow
    let new_to_balance = to_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    // Safe to write
    // ...
}
```

## Rust Checked Arithmetic Methods

| Operation | Unchecked (Dangerous) | Checked (Safe) |
|-----------|----------------------|----------------|
| Addition | `a + b` | `a.checked_add(b)` |
| Subtraction | `a - b` | `a.checked_sub(b)` |
| Multiplication | `a * b` | `a.checked_mul(b)` |
| Division | `a / b` | `a.checked_div(b)` |
| Power | `a.pow(b)` | `a.checked_pow(b)` |

All checked methods return `Option<T>`:
- `Some(result)` if operation succeeded
- `None` if overflow/underflow occurred

## Other Safe Arithmetic Options

### Saturating Operations
```rust
// Clamps at min/max instead of wrapping
let result = a.saturating_add(b);  // MAX if overflow
let result = a.saturating_sub(b);  // 0 if underflow
```

### Wrapping Operations (Explicit)
```rust
// Explicitly wraps (documents intent)
let result = a.wrapping_add(b);
```

### Overflowing Operations
```rust
// Returns (result, did_overflow)
let (result, overflowed) = a.overflowing_add(b);
if overflowed {
    return Err(Error::Overflow);
}
```

## Prevention Checklist

- [ ] Use `checked_*` methods for ALL arithmetic operations
- [ ] Handle the `None` case with proper error
- [ ] Use larger types (u128) for intermediate calculations
- [ ] Add explicit bounds checking before operations
- [ ] Test with edge cases: 0, 1, MAX-1, MAX
- [ ] Consider using saturating operations where appropriate
- [ ] Review all places where user input affects calculations

## Common Vulnerable Patterns

### Pattern 1: Direct Subtraction
```rust
// ❌ BAD
balance = balance - withdrawal;

// ✅ GOOD
balance = balance.checked_sub(withdrawal).ok_or(Error)?;
```

### Pattern 2: Fee Calculation
```rust
// ❌ BAD - multiplication can overflow
let fee = amount * fee_rate / 10000;

// ✅ GOOD - use u128 or checked operations
let fee = (amount as u128 * fee_rate as u128 / 10000) as u64;
```

### Pattern 3: Loop Counters
```rust
// ❌ BAD - can wrap
for i in 0..user_input {
    // ...
}

// ✅ GOOD - validate input first
require!(user_input <= MAX_ITERATIONS, Error::TooManyIterations);
```

### Pattern 4: Time Calculations
```rust
// ❌ BAD - can overflow
let unlock_time = current_time + lock_duration;

// ✅ GOOD
let unlock_time = current_time.checked_add(lock_duration).ok_or(Error)?;
```

## Real-World Impact

Integer overflow bugs have caused:
- **Fund theft** through balance manipulation
- **Fee bypass** by overflowing fee calculations  
- **Denial of service** through panic in debug builds
- **Economic exploits** in DeFi protocols

## References

- [Rust Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Integer Overflow Attack Examples](https://github.com/coral-xyz/sealevel-attacks)