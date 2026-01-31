# Integer Overflow/Underflow - Test Scenarios

This document demonstrates how to test the vulnerability and verify the fix.

## Background

In Rust **release mode** (how Solana programs run), integer overflow/underflow **wraps silently** without any error:
```
u64 underflow: 0 - 1 = 18,446,744,073,709,551,615 (u64::MAX)
u64 overflow:  u64::MAX + 1 = 0
```

This is catastrophic for balance calculations!

---

## Test Setup
```typescript
import * as anchor from "@coral-xyz/anchor";
import { Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";

const user = Keypair.generate();
const vault = Keypair.generate();

// Key constants
const U64_MAX = new anchor.BN("18446744073709551615");
```

---

## Test 1: ❌ EXPLOIT - Underflow Attack

### Scenario
User withdraws MORE than their balance, causing underflow to massive number.

### Attack Flow
```
1. User has vault with balance = 100 tokens
2. User requests withdrawal of 101 tokens
3. Vulnerable code calculates: 100 - 101
4. In release mode: 100 - 101 = 18,446,744,073,709,551,615 (WRAPPED!)
5. ❌ User now has mass balance!
```

### Vulnerable Code Being Exploited
```rust
// ❌ VULNERABLE: Direct subtraction can underflow
pub fn withdraw_vulnerable(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ NO UNDERFLOW CHECK!
    // If amount > balance, this wraps to huge number
    vault.balance = vault.balance - amount;
    
    // User now has mass tokens!
}
```

### Test Code
```typescript
it("❌ EXPLOIT: Underflow gives user mass balance", async () => {
  // Setup: User has 100 tokens
  const initialBalance = 100;
  await initializeVault(vault, user, initialBalance);

  // Verify initial balance
  let vaultAccount = await program.account.vault.fetch(vault.publicKey);
  expect(vaultAccount.balance.toNumber()).to.equal(100);

  // ATTACK: Withdraw MORE than balance
  const withdrawAmount = 101;  // More than the 100 we have!
  
  await program.methods
    .withdrawVulnerable(new anchor.BN(withdrawAmount))
    .accounts({
      vault: vault.publicKey,
      owner: user.publicKey,
    })
    .signers([user])
    .rpc();

  // Check balance after "withdrawal"
  vaultAccount = await program.account.vault.fetch(vault.publicKey);
  
  // ❌ EXPLOIT RESULT:
  // Expected (correct): Error - insufficient funds
  // Actual (vulnerable): 100 - 101 = 18,446,744,073,709,551,515
  
  console.log("Balance after underflow:", vaultAccount.balance.toString());
  // Output: 18446744073709551515
  
  // Balance is now mass (near u64::MAX)!
  expect(vaultAccount.balance.gt(new anchor.BN("18000000000000000000"))).to.be.true;
});
```

### Expected Result (Vulnerable Code)
- ❌ Transaction **SUCCEEDS** (should fail!)
- ❌ Balance becomes `18,446,744,073,709,551,515` instead of error
- ❌ User has mass "free" tokens

---

## Test 2: ❌ EXPLOIT - Overflow Attack

### Scenario
Deposit amount that causes balance to wrap to small number.

### Attack Flow
```
1. User has vault with balance = 100 tokens
2. User deposits (u64::MAX - 50) tokens
3. Vulnerable code calculates: 100 + (u64::MAX - 50)
4. In release mode: Result wraps to 49!
5. ❌ User's balance decreased instead of increased!
```

### Vulnerable Code Being Exploited
```rust
// ❌ VULNERABLE: Direct addition can overflow
pub fn deposit_vulnerable(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ NO OVERFLOW CHECK!
    // If balance + amount > u64::MAX, wraps to small number
    vault.balance = vault.balance + amount;
}
```

### Test Code
```typescript
it("❌ EXPLOIT: Overflow wraps balance to small number", async () => {
  // Setup: User has 100 tokens
  const initialBalance = 100;
  await initializeVault(vault, user, initialBalance);

  // ATTACK: Deposit amount that causes overflow
  // u64::MAX - 50 + 100 = u64::MAX + 50 = 49 (wrapped!)
  const maliciousDeposit = U64_MAX.sub(new anchor.BN(50));
  
  await program.methods
    .depositVulnerable(maliciousDeposit)
    .accounts({
      vault: vault.publicKey,
      owner: user.publicKey,
    })
    .signers([user])
    .rpc();

  // Check balance after "deposit"
  const vaultAccount = await program.account.vault.fetch(vault.publicKey);
  
  // ❌ EXPLOIT RESULT:
  // Expected (correct): Error - overflow
  // Actual (vulnerable): 100 + (MAX-50) = 49 (wrapped!)
  
  console.log("Balance after overflow:", vaultAccount.balance.toString());
  // Output: 49
  
  // Balance DECREASED instead of increased!
  expect(vaultAccount.balance.toNumber()).to.equal(49);
});
```

### Expected Result (Vulnerable Code)
- ❌ Transaction **SUCCEEDS** (should fail!)
- ❌ Balance becomes `49` instead of error
- ❌ User lost tokens by "depositing"

---

## Test 3: ✅ FIX - Underflow Prevented

### Scenario
Same underflow attack attempted against secure code - **REJECTED**.

### Secure Code
```rust
// ✅ SECURE: checked_sub returns None on underflow
pub fn withdraw_secure(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ checked_sub returns None if amount > balance
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(VaultError::InsufficientBalance)?;
    
    // If we get here, subtraction was safe
}
```

### Test Code
```typescript
it("✅ FIX: Underflow attempt is rejected", async () => {
  // Setup: User has 100 tokens
  await initializeVault(vault, user, 100);

  // ATTACK ATTEMPT: Withdraw more than balance
  try {
    await secureProgram.methods
      .withdrawSecure(new anchor.BN(101))  // More than 100!
      .accounts({
        vault: vault.publicKey,
        owner: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    // Should never reach here!
    expect.fail("Transaction should have failed");
  } catch (error) {
    // ✅ EXPECTED: Transaction rejected with underflow error
    expect(error.message).to.include("InsufficientBalance");
  }

  // Verify balance unchanged
  const vaultAccount = await secureProgram.account.vault.fetch(vault.publicKey);
  expect(vaultAccount.balance.toNumber()).to.equal(100);
  
  console.log("✅ Underflow prevented - balance still 100");
});
```

### Expected Result (Secure Code)
- ✅ Transaction **FAILS** with "InsufficientBalance"
- ✅ Balance remains `100`
- ✅ No underflow occurred

---

## Test 4: ✅ FIX - Overflow Prevented

### Scenario
Same overflow attack attempted against secure code - **REJECTED**.

### Secure Code
```rust
// ✅ SECURE: checked_add returns None on overflow
pub fn deposit_secure(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ checked_add returns None if result > u64::MAX
    vault.balance = vault.balance
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
}
```

### Test Code
```typescript
it("✅ FIX: Overflow attempt is rejected", async () => {
  // Setup: User has 100 tokens
  await initializeVault(vault, user, 100);

  // ATTACK ATTEMPT: Deposit amount causing overflow
  const maliciousDeposit = U64_MAX.sub(new anchor.BN(50));
  
  try {
    await secureProgram.methods
      .depositSecure(maliciousDeposit)
      .accounts({
        vault: vault.publicKey,
        owner: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    expect.fail("Transaction should have failed");
  } catch (error) {
    // ✅ EXPECTED: Transaction rejected with overflow error
    expect(error.message).to.include("ArithmeticOverflow");
  }

  // Verify balance unchanged
  const vaultAccount = await secureProgram.account.vault.fetch(vault.publicKey);
  expect(vaultAccount.balance.toNumber()).to.equal(100);
  
  console.log("✅ Overflow prevented - balance still 100");
});
```

### Expected Result (Secure Code)
- ✅ Transaction **FAILS** with "ArithmeticOverflow"
- ✅ Balance remains `100`
- ✅ No overflow occurred

---

## Test 5: ✅ Legitimate Operations

### Test Code
```typescript
it("✅ LEGITIMATE: Normal deposits and withdrawals work", async () => {
  // Setup: User has 100 tokens
  await initializeVault(vault, user, 100);

  // Deposit 50 (no overflow)
  await secureProgram.methods
    .depositSecure(new anchor.BN(50))
    .accounts({ vault: vault.publicKey, owner: user.publicKey })
    .signers([user])
    .rpc();

  let vaultAccount = await secureProgram.account.vault.fetch(vault.publicKey);
  expect(vaultAccount.balance.toNumber()).to.equal(150);

  // Withdraw 75 (no underflow)
  await secureProgram.methods
    .withdrawSecure(new anchor.BN(75))
    .accounts({ vault: vault.publicKey, owner: user.publicKey })
    .signers([user])
    .rpc();

  vaultAccount = await secureProgram.account.vault.fetch(vault.publicKey);
  expect(vaultAccount.balance.toNumber()).to.equal(75);
  
  console.log("✅ Legitimate operations work correctly");
});
```

---

## Summary

| Test | Vulnerable Code | Secure Code |
|------|----------------|-------------|
| Withdraw > balance (underflow) | ❌ Wraps to u64::MAX | ✅ Rejected |
| Deposit causing overflow | ❌ Wraps to small number | ✅ Rejected |
| Normal deposit | ✅ Works | ✅ Works |
| Normal withdraw | ✅ Works | ✅ Works |

### Key Difference
```rust
// ❌ VULNERABLE - Direct operators
vault.balance = vault.balance - amount;  // Can underflow!
vault.balance = vault.balance + amount;  // Can overflow!

// ✅ SECURE - Checked arithmetic
vault.balance = vault.balance.checked_sub(amount).ok_or(Error)?;
vault.balance = vault.balance.checked_add(amount).ok_or(Error)?;
```

### Visual: Underflow Example
```
Balance: 100
Withdraw: 101

❌ VULNERABLE:  100 - 101 = 18,446,744,073,709,551,515
✅ SECURE:     100 - 101 = ERROR (InsufficientBalance)
```

### Visual: Overflow Example
```
Balance: 100
Deposit: 18,446,744,073,709,551,565 (u64::MAX - 50)

❌ VULNERABLE:  100 + (MAX-50) = 49 (wrapped!)
✅ SECURE:     100 + (MAX-50) = ERROR (ArithmeticOverflow)
```