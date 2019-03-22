pragma solidity 0.4.25;

contract Owned {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
    *  Constructor
    *
    *  Sets contract owner to address of constructor caller
    */
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
    *  Change Owner
    *
    *  Changes ownership of this contract. Only owner can call this method.
    *
    * @param newOwner - new owner's address
    */
    function changeOwner(address newOwner) onlyOwner public {
        require(newOwner != address(0));
        require(newOwner != owner);
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
