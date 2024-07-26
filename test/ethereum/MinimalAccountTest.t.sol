//SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MinimalAccount} from "src/ethereum/MinimalAccount.sol";
import {DeployMinimal} from "script/DeployMinimal.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks//token/ERC20Mock.sol";

contract MinimalAccountTest is Test {
    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    ERC20Mock usdc;

    address nonOwnerUser = makeAddr("random");

    uint256 constant USDC_MINT_AMOUNT = 1e18;

    function setUp() public {
        DeployMinimal deployMinimal = new DeployMinimal();
        (helperConfig, minimalAccount) = deployMinimal.deployMinimalAccount();
        usdc = new ERC20Mock();
    }

    //USDC Mint
    //msg.sender -> minimalaccount
    //approve some amount
    //USDC contract
    //come from the entrypoint

    function testOwnerCanExecuteCommands() public {
        //arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), USDC_MINT_AMOUNT);

        //Account
        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, functionData);

        //assert
        assertEq(usdc.balanceOf(address(minimalAccount)), USDC_MINT_AMOUNT);
    }

    function testNonOwnerCannotExecuteCommands() public {
        //arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData =
            abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), USDC_MINT_AMOUNT);

        //Account
        vm.prank(nonOwnerUser);
        vm.expectRevert("MinimalAccount: only entryPoint or owner can call this function");
        minimalAccount.execute(dest, value, functionData);
    }
}
