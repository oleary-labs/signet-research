// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISignetGroup
/// @notice Interface for a Signet threshold signing group deployed via BeaconProxy.
interface ISignetGroup {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    enum NodeStatus { None, Pending, Active }

    struct RemovalRequest {
        uint256 executeAfter;
        address initiator;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event NodeInvited(address indexed node, address indexed invitedBy);
    event NodeJoined(address indexed node);
    event NodeDeclined(address indexed node);
    event RemovalQueued(address indexed node, address indexed initiator, uint256 executeAfter);
    event RemovalCancelled(address indexed node, address indexed cancelledBy);
    event NodeRemoved(address indexed node);
    event ManagerTransferred(address indexed oldManager, address indexed newManager);

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    /// @notice Initialize the group (called once through the BeaconProxy constructor data).
    function initialize(
        address _manager,
        address[] calldata nodeAddrs,
        uint256 _threshold,
        uint256 _removalDelay,
        address _factory
    ) external;

    // -------------------------------------------------------------------------
    // Membership management
    // -------------------------------------------------------------------------

    /// @notice Invite a registered node post-creation.
    function inviteNode(address node) external;

    /// @notice Accept an existing pending invitation (caller must be the pending node).
    function acceptInvite() external;

    /// @notice Decline a pending invitation (caller must be the pending node).
    function declineInvite() external;

    /// @notice Queue a removal for an active node (manager or node itself).
    function queueRemoval(address node) external;

    /// @notice Cancel a queued removal (manager or original initiator).
    function cancelRemoval(address node) external;

    /// @notice Execute a removal after its delay has elapsed (permissionless).
    function executeRemoval(address node) external;

    /// @notice Transfer the manager role to another address.
    function transferManager(address newManager) external;

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    function factory() external view returns (address);
    function manager() external view returns (address);
    function threshold() external view returns (uint256);
    function removalDelay() external view returns (uint256);
    function nodeStatus(address node) external view returns (NodeStatus);
    function removalRequests(address node) external view returns (RemovalRequest memory);
    function getActiveNodes() external view returns (address[] memory);
    function getPendingNodes() external view returns (address[] memory);
    function getPendingRemovals() external view returns (address[] memory);

    /// @notice Returns threshold + 1.
    function quorum() external view returns (uint256);

    /// @notice True when active node count >= quorum().
    function isOperational() external view returns (bool);
}
