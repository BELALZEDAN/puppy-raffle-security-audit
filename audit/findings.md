### [H-1] Missing Zero Address Check in `enterRaffle` (Security + High Impact)

**Description**  
The `enterRaffle` function allows adding any address to the players array without checking if the address is `0x0`. This means an attacker or by mistake, `address(0)` can be added as a player, which can cause issues later in withdrawals or winner selection.

**Impact**  
- Adding `address(0)` can break the `refund` function for that player.  
- The `selectWinner` function might pick a zero address as a winner → funds can be lost.  
- ETH could be locked in the contract if prizes or fees are sent to invalid addresses.

**Proof of Concept**  
1. Call `enterRaffle([address(0)])` with the correct `msg.value`.  
2. Attempt to call `refund` for this player → function may fail or behave unexpectedly.  
3. Call `selectWinner` → zero address could be selected → ETH sent to 0x0.

**Recommended Mitigation**  
- Add a check to ensure no zero addresses are added:

```javascript
require(newPlayers[i] != address(0), "PuppyRaffle: Cannot add zero address");
```
Preferably combine this check with the duplicate check in the same loop to save gas.

---