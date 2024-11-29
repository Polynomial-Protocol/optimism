// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Predeploys } from "../libraries/Predeploys.sol";
import { Semver } from "../universal/Semver.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IPyth } from "./IPyth.sol";

/**
 * @custom:proxied
 * @custom:predeploy 0x42000000000000000000000000000000000000A1
 * @title Tick
 * @notice The Tick predeploy ticks the chain.
 */
contract Pyth is Semver, Ownable, IPyth {
    /**
     * @notice Address of the special depositor account.
     */
    address public constant DEPOSITOR_ACCOUNT = 0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001;

    /**
     * @notice Address of the tick contract to be called.
     */
    address public pyth;

    /**
     * @param _owner Address that will initially own this contract.
     * @custom:semver 0.0.1
     */
    constructor(address _owner) Ownable() Semver(0, 0, 1) {
        transferOwnership(_owner);
    }

    /**
     * @notice Allows the owner to modify the target address.
     * @param _target New target address.
     */
    function setPyth(address _pyth) public onlyOwner {
        pyth = _pyth;
    }

    /**
     * @notice Calls the tick function in the target contract.
     */
    function updatePriceFeed(
        bytes[] calldata updateData
    ) public payable override {
        require(msg.sender == DEPOSITOR_ACCOUNT, "Price feed update: only the depositor account can update");
        if (pyth == address(0)) {
            return;
        }
        IPyth(pyth).updatePriceFeed();
    }
}
