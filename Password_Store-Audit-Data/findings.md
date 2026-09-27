# PasswordStore Audit Findings

| ID | Title | Severity |
| --- | --- | --- |
| [H-1](#h-1-on-chain-password-storage-is-publicly-readable-regardless-of-the-private-visibility-specifier) | On-chain password storage is publicly readable regardless of the `private` visibility specifier | High |
| [H-2](#h-2-missing-access-control-on-setpassword-allows-anyone-to-overwrite-the-stored-password) | Missing access control on `setPassword` allows anyone to overwrite the stored password | High |
| [L-1](#l-1-the-constructor-does-not-set-an-initial-password-so-the-store-is-empty-until-the-first-setpassword) | The constructor does not set an initial password, so the store is empty until the first `setPassword` | Low |
| [I-1](#i-1-incorrect-natspec-on-getpassword-documents-a-parameter-the-function-does-not-accept) | Incorrect NatSpec on `getPassword` documents a parameter the function does not accept | Informational |

---

### [H-1] On-chain password storage is publicly readable regardless of the `private` visibility specifier

**Description:** `PasswordStore::s_password` is declared `private` and is only meant to be returned to the owner through `PasswordStore::getPassword`. That visibility specifier does **not** keep the value secret.

On Ethereum, every contract storage slot is public. `private` only prevents other *contracts* from reading the variable in Solidity. Anyone can still read the slot directly from a node, a block explorer, or tools such as `cast storage`.

The protocol’s stated goal is that “others won’t be able to see” the password. Storing the plaintext password on-chain breaks that guarantee, even if `getPassword` correctly restricts callers.

```solidity
address private s_owner;
// @audit storage is public on-chain; `private` does not hide this value
string private s_password;
```

**Impact:** Any observer can recover the stored password. This breaks the core product promise of a private password store and fully compromises confidentiality.

**Proof of Concept:**

1. Start a local node:

```bash
anvil
```

2. Deploy the contract:

```bash
make deploy
```

3. Read storage slot `1` (`s_password`). On a default Anvil deployment the contract address is `0x5FbDB2315678afecb367f032d93F642f64180aa3`:

```bash
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 1 --rpc-url 127.0.0.1:8545
```

Example result (bytes32):

```text
0x6d7950617373776f726400000000000000000000000000000000000000000014
```

4. Decode the bytes32 value to a string:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

Result:

```text
myPassword
```

The password is readable without calling `getPassword` and without being the owner.

**Recommended Mitigation:** A password cannot be kept secret if it is stored in plaintext on-chain. The architecture needs to change.

One option is to keep the password off-chain, encrypt it, and store only the ciphertext (or a hash) on-chain. That design would require the owner to remember a separate secret used for decryption.

If the password is encrypted off-chain, consider removing the on-chain view function as well. An owner who later calls a decrypt-and-return helper from a public node or explorer could still leak the plaintext.

---

### [H-2] Missing access control on `setPassword` allows anyone to overwrite the stored password

**Description:** `PasswordStore::setPassword` has no owner check. The NatSpec and protocol design say that only the owner should be able to store or update the password, but the function is `external` and accepts a call from any address.

```solidity
function setPassword(string memory newPassword) external {
    // @audit no access control; any caller can overwrite s_password
    s_password = newPassword;
    emit SetNetPassword();
}
```

`getPassword` correctly reverts for non-owners with `PasswordStore__NotOwner`, but `setPassword` never performs that check.

**Impact:** Any address can overwrite the stored password. The owner can lose control of the value they intended to keep, and the contract no longer behaves as a single-user password store.

**Proof of Concept:** Add the following test to `PasswordStore.t.sol`:

<details>
<summary>Code</summary>

```solidity
function test_anyone_can_set_password(address randomAddress) public {
    vm.assume(randomAddress != owner);
    vm.prank(randomAddress);
    string memory expectedPassword = "myNewPassword";
    passwordStore.setPassword(expectedPassword);
    vm.prank(owner);
    string memory actualPassword = passwordStore.getPassword();
    assertEq(actualPassword, expectedPassword);
}
```

</details>

The test passes: a non-owner sets the password, and the owner later reads that attacker-controlled value.

**Recommended Mitigation:** Enforce the same owner check used in `getPassword`:

```solidity
if (msg.sender != s_owner) {
    revert PasswordStore__NotOwner();
}
```

A dedicated `onlyOwner` modifier is also acceptable if the team prefers that style.

---

### [L-1] The constructor does not set an initial password, so the store is empty until the first `setPassword`

**Description:** `PasswordStore` sets `s_owner` in the constructor but never sets `s_password`. Until someone calls `setPassword`, the stored value is the empty string.

```solidity
constructor() {
    s_owner = msg.sender;
}
```

That gap matters more because of [H-2](#h-2-missing-access-control-on-setpassword-allows-anyone-to-overwrite-the-stored-password): any address can make the first write. Even after an owner-set password, on-chain data remains public, as described in [H-1](#h-1-on-chain-password-storage-is-publicly-readable-regardless-of-the-private-visibility-specifier).

**Impact:** Between deployment and the first `setPassword`, the store has no owner-chosen secret. If a non-owner writes first, the owner later reads an attacker-controlled value.

**Proof of Concept:** Deploy the contract and call `getPassword` as the owner before any `setPassword`. The return value is empty.

**Recommended Mitigation:** Accept an initial password in the constructor (or a one-time initializer restricted to the owner) so the store is never empty after deployment. This does not replace the access-control and on-chain-secrecy fixes.

---

### [I-1] Incorrect NatSpec on `getPassword` documents a parameter the function does not accept

**Description:** The comment above `PasswordStore::getPassword` includes `@param newPassword The new password to set`. `getPassword` takes no parameters and does not set a password. The documentation incorrectly implies a signature such as `getPassword(string)`.

```solidity
/*
 * @notice This allows only the owner to retrieve the password.
 * @param newPassword The new password to set.
 */
function getPassword() external view returns (string memory) {
```

**Impact:** Developers, auditors, and generated docs will be misled about the function’s interface and purpose. This is a documentation error, not a runtime vulnerability.

**Recommended Mitigation:** Remove the incorrect `@param` line.

```diff
- * @param newPassword The new password to set.
```
