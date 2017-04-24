pragma solidity ^0.4.8;

// Standard token interface

contract ERC20 {
    event Transfer(address indexed from, address indexed to, uint value);
    event Approval( address indexed owner, address indexed spender, uint value);
    function totalSupply() constant returns (uint supply);
    function balanceOf( address who ) constant returns (uint value);
    function allowance(address owner, address spender) constant returns (uint _allowance);   
    function transfer( address to, uint value) returns (bool ok);
    function transferFrom( address from, address to, uint value) returns (bool ok);
    function approve(address spender, uint value) returns (bool ok);
}

// magicSquared: Bounty contract for finding a 3 by 3 magic square resulting from squared numbers
// - no repeat numbers allowed
// - to submit a solution first sha3 hash it : sha3(addressOfsubmitter, board[0],board[1],board[2],board[3],board[4],board[5],board[6],board[7],board[8])
//   then call commit with that hash this sets up an interval of 48 hours after which you can submit the solution in the clear
//   with 48 hours for it to confirm before somone else could have waited the same period of time
// - once a solution is found the solution provider owns the contract and can remove all ETH and token funds. No furter solutions can be submitted. 
//
//   Warning: all functions that take in the board should be called locally unless the board hash is already claimed
//   calling the helper function getHash() will reveal the board to a hosted service that performs the function calculation
//   same goes for isMagicSquareOfSquaredNumbers() and hasNoDuplicates()
//
//   This bounty will not work for solutions with a magic sum 2^256 or higher. Arbitrary sized integer libraries needed
//
//   This contract is dedicated to the Parker Square: "at least he tried" 
//
//   All source is covered by the MIT license 


contract magicSquared {
    
    uint[9] public solution;
    address public owner = 0x0; // no owner to begin with

    mapping(bytes32 => uint) public unlockTime;
    
    uint public unlockInterval = 30 minutes; 
    uint constant public increaseIntervalBond = 1 ether;

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }
    
    event SolutionFound(address finder, uint[9] board, string message);
    event DonationMessage(address donor, string message);
    
    mapping(address => uint) donatorBalance;
    
    //----------------------------------------------
    // increase inteval up to 2 days, default is 30 minutes
    
    function increaseInterval(uint256 newInterval) payable 
    {
        if(msg.value < increaseIntervalBond) throw;
        if(newInterval > 2 days) throw;
        if(newInterval < unlockInterval) throw;
        unlockInterval = newInterval;
    }

    //----------------------------------------------
    // donate ETH to bounty
    
    function recordDonation() internal {
        donatorBalance[msg.sender] = safeAdd(donatorBalance[msg.sender], msg.value);
    }
    
    function () payable {
        recordDonation();
    }
    
    function donate(string message) payable {
        recordDonation();
        DonationMessage(msg.sender, message);
    }
    
    // refund donation
    function refund(uint amount) 
    {
        if(owner != 0x0) throw; // cannot refund once a solution is found
        donatorBalance[msg.sender] = safeSub(donatorBalance[msg.sender], amount); // throws if funds insufficient 
        if(!msg.sender.send(amount)) throw; // send donator their refund, revert if out of gas in external call. 
    }
    
    //----------------------------------------------
    // owner claim's funds functions
    
    // owner withdraws all ETH
    function withdrawEther() onlyOwner {
        if(!owner.send(this.balance)) throw;
    }
    
    // owner withdraws all tokens at given token address
    function withdrawToken(ERC20 token) onlyOwner {
        if(!token.transfer(owner,token.balanceOf(owner))) throw;
    }
    
    // owner withdraws specific amount of tokens at given token address
    // just incase balanceOf gives incorrect amount:
    // use this for tokens that add additional token fee onto transaction
    function withdrawTokenAmount(ERC20 token, uint amount) onlyOwner {
        if(!token.transfer(owner,amount)) throw;
    }
    
    //----------------------------------------------
    // overflow checking
    
    function assert(bool assertion) internal {
        if (!assertion) {
          throw;
        }
    }
    
    function safeMul(uint a, uint b) internal returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }
    
    function safeSquare(uint a) internal returns (uint) {
        return safeMul(a,a);
    }
    
    
    function safeAdd(uint a, uint b) internal returns (uint) {
        uint c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
    
    
    function safeAdd3(uint a, uint b, uint c) internal returns (uint) {
        return safeAdd(safeAdd(a,b),c);
    }
    
    function safeSub(uint a, uint b) internal returns (uint) {
        assert(b <= a);
        return a - b;
    }
    
    //----------------------------------------------
    // reward claim functions
    
    function isMagicSquareOfSquaredNumbers(uint[9] board) constant returns (bool) {
        
        uint aa = safeSquare(board[0]);
        uint ab = safeSquare(board[1]);
        uint ac = safeSquare(board[2]);
        
        uint ba = safeSquare(board[3]);
        uint bb = safeSquare(board[4]);
        uint bc = safeSquare(board[5]);
        
        uint ca = safeSquare(board[6]);
        uint cb = safeSquare(board[7]);
        uint cc = safeSquare(board[8]);

        uint magic_sum = safeAdd3(aa,bb,cc); // top left diagonal
        
        if(magic_sum != safeAdd3(ac,bb,ca)) return false; // top right diagonal
        
        if(magic_sum != safeAdd3(aa,ab,ac)) return false; // rows
        if(magic_sum != safeAdd3(ba,bb,bc)) return false;
        if(magic_sum != safeAdd3(ca,cb,cc)) return false;
        
        if(magic_sum != safeAdd3(aa,ba,ca)) return false; // columns
        if(magic_sum != safeAdd3(ab,bb,cb)) return false;
        if(magic_sum != safeAdd3(ac,bc,cc)) return false;
        
        return true;
    }
    
    // test if a board has duplicate values by checking every element with the elements after it
    function hasNoDuplicates(uint[9] board) constant returns (bool) 
    {
        for(uint i = 0; i < 9; i++) {
            for(uint j = i+1; j < 9; j++) {
                if(board[i] == board[j]) return false;
            }
        }
        
        return true;
    }
    
    // hash a board, call locally if you have a solution dont let a server steal your solution!
    function getHash(uint[9] board, uint256 secret, address claimer) constant returns (bytes32) 
    {
        return sha3(board[0],board[1],board[2],board[3],board[4],board[5],board[6],board[7],board[8], secret,claimer);
    }
    
    // lock in the hash of a booard without revealing the board
    // sets an unlock time for a specific hash
    function commit(bytes32 hash) {
        if(unlockTime[hash] != 0) throw;
        unlockTime[hash] = now + unlockInterval;
    }
    
    // after you have locked in a board hash call this to claim ownership of the contract with the correct solution
    function claim(uint[9] board, uint256 secret, string message) {
        
        if(owner != 0x0) throw; // a solution has already been found   
        
        var unlockdate = unlockTime[getHash(board,secret,msg.sender)];
        
        if(unlockdate == 0) throw;  // must have lock time set
        if(unlockdate > now) throw; // must be after the locked period
        
        if(isMagicSquareOfSquaredNumbers(board) && hasNoDuplicates(board)) 
        {
            owner = msg.sender;
            solution = board;
            SolutionFound(msg.sender, board, message);
        }
    }
}
