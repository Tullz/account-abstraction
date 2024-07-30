//SPDX-License-Identifier: MIT

import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from
    "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS,
    DEPLOYER_SYSTEM_CONTRACT
} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {Utils} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

pragma solidity ^0.8.24;

contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZKMinimalAcccount__NotEnoughBalance();
    error ZkminimalAccount__NotFromBootloader();
    error ZkMinimalAccount__ExecutionFailed();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier requireFromBootLoader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkminimalAccount__NotFromBootloader();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     *
     * @notice must increase the nonce
     * @notice must validation the transaction
     * @notice check to see if we have enough money in account to pay
     */
    function validateTransaction(bytes32 _txHash, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
        requireFromBootLoader
        returns (bytes4 magic)
    {
        // this increments the nonce
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        //check for fee
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZKMinimalAcccount__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash();
        // bytes32 convertedHash = MessageHashUtils.toEthSignedMessageHash(txHash);
        address signer = ECDSA.recover(txHash, _transaction.signature);
        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
        return magic;
    }

    function executeTransaction(
        bytes32, /*_txHash*/
        bytes32, /*_suggestedSignedHash*/
        Transaction calldata _transaction
    ) external payable {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;
            assembly {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }

            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }

    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {}

    function payForTransaction(bytes32 _txHash, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    function prepareForPaymaster(bytes32 _txHash, bytes32 _possibleSignedHash, Transaction calldata _transaction)
        external
        payable
    {}

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
}
