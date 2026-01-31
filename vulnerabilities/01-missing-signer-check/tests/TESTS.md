# Missing Signer Check - Test Scenarios

This document demonstrates how to test the vulnerability and verify the fix.

## Test Setup
```typescript
// Required imports for Anchor tests
import * as anchor from "@coral-xyz/anchor";
import { Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";

// Test accounts
const alice = Keypair.generate();      // Legitimate vault owner
const attacker = Keypair.generate();   // Malicious actor
const vault = Keypair.generate();      // Vault account
```

---

## Test 1: ❌ EXPLOIT - Vulnerable Code

### Scenario
Attacker withdraws funds WITHOUT the owner's signature.

### Attack Flow
```
1. Alice creates vault with authority = Alice.publicKey
2. Alice deposits 5 SOL
3. Attacker calls withdraw_vulnerable():
   - Passes Alice's pubkey as "authority" (not a signer!)
   - Attacker signs the transaction (not Alice)
4. Vulnerable code checks: authority.key() == vault.authority? ✓ YES
5. Vulnerable code does NOT check: authority.is_signer()
6. ❌ EXPLOIT SUCCEEDS - Attacker steals funds!
```

### Vulnerable Code Being Exploited
```rust
// ❌ VULNERABLE: UncheckedAccount doesn't verify signature
pub authority: UncheckedAccount<'info>,

pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let authority = &ctx.accounts.authority;
    
    // ❌ Only checks pubkey matches - NOT signature!
    if authority.key() != vault.authority {
        return Err(VaultError::InvalidAuthority.into());
    }
    
    // ❌ MISSING: if !authority.is_signer() { return Err(...) }
    
    // Attacker passes Alice's pubkey but doesn't need her signature
    // Funds transferred to attacker!
}
```

### Test Code
```typescript
it("❌ EXPLOIT: Attacker withdraws without owner signature", async () => {
  // Setup: Alice creates and funds vault
  await program.methods
    .initializeVault()
    .accounts({ vault: vault.publicKey, authority: alice.publicKey })
    .signers([alice, vault])
    .rpc();

  await program.methods
    .deposit(new anchor.BN(5 * LAMPORTS_PER_SOL))
    .accounts({ vault: vault.publicKey, authority: alice.publicKey })
    .signers([alice])
    .rpc();

  // ATTACK: Attacker calls withdraw with Alice's pubkey
  // but signs with their own key!
  await program.methods
    .withdrawVulnerable(new anchor.BN(5 * LAMPORTS_PER_SOL))
    .accounts({
      vault: vault.publicKey,
      authority: alice.publicKey,  // Alice's pubkey (not signing!)
      destination: attacker.publicKey,
    })
    .signers([attacker])  // Attacker signs (not Alice!)
    .rpc();

  // ❌ EXPLOIT SUCCEEDS - Attacker stole the funds!
  const attackerBalance = await provider.connection.getBalance(attacker.publicKey);
  expect(attackerBalance).to.be.greaterThan(5 * LAMPORTS_PER_SOL);
});
```

### Expected Result
- ❌ Transaction **SUCCEEDS** (vulnerability!)
- ❌ Attacker receives Alice's 5 SOL

---

## Test 2: ✅ FIX - Secure Code

### Scenario
Same attack attempted against secure code - **REJECTED**.

### Defense Flow
```
1. Alice creates vault with authority = Alice.publicKey
2. Attacker tries same exploit
3. Secure code uses Signer<'info> type
4. Anchor automatically checks: did authority sign? ✗ NO
5. ✅ Transaction REJECTED - "Missing required signature"
6. Alice's funds are safe!
```

### Secure Code
```rust
// ✅ SECURE: Signer type enforces signature verification
pub authority: Signer<'info>,

pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    // By the time we get here, Anchor has ALREADY verified
    // that authority signed the transaction!
    
    let vault = &ctx.accounts.vault;
    // Safe to proceed - signature was verified
}
```

### Test Code
```typescript
it("✅ FIX: Attacker's withdrawal attempt is rejected", async () => {
  // Setup: Alice creates and funds vault (same as before)
  
  // ATTACK ATTEMPT against secure program
  try {
    await secureProgram.methods
      .withdrawSecure(new anchor.BN(5 * LAMPORTS_PER_SOL))
      .accounts({
        vault: vault.publicKey,
        authority: alice.publicKey,  // Alice's pubkey
        destination: attacker.publicKey,
      })
      .signers([attacker])  // Attacker signs (not Alice!)
      .rpc();
    
    // Should never reach here!
    expect.fail("Transaction should have failed");
  } catch (error) {
    // ✅ EXPECTED: Transaction rejected
    expect(error.message).to.include("Signature verification failed");
  }
});
```

### Expected Result
- ✅ Transaction **FAILS**
- ✅ Error: "Signature verification failed" or "Missing required signature"
- ✅ Alice's funds remain safe

---

## Test 3: ✅ Legitimate Withdrawal

### Scenario
Owner withdraws their own funds with proper signature.

### Test Code
```typescript
it("✅ LEGITIMATE: Owner withdraws with signature", async () => {
  // Alice withdraws her own funds, signing with her key
  await secureProgram.methods
    .withdrawSecure(new anchor.BN(5 * LAMPORTS_PER_SOL))
    .accounts({
      vault: vault.publicKey,
      authority: alice.publicKey,
      destination: alice.publicKey,
    })
    .signers([alice])  // Alice signs!
    .rpc();

  // ✅ SUCCESS - Alice receives her funds
});
```

### Expected Result
- ✅ Transaction **SUCCEEDS**
- ✅ Alice receives her funds

---

## Summary

| Test | Vulnerable Code | Secure Code |
|------|----------------|-------------|
| Attacker tries to withdraw | ❌ Succeeds (BUG!) | ✅ Rejected |
| Owner withdraws | ✅ Succeeds | ✅ Succeeds |

### Key Difference
```rust
// ❌ VULNERABLE
pub authority: UncheckedAccount<'info>  // No signature check!

// ✅ SECURE  
pub authority: Signer<'info>            // Automatic signature check!
```