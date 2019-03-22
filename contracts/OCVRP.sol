pragma solidity 0.4.25;
import './Owned.sol';

contract OCVRP {

    struct Poll {
        address relay;
        uint8 options;
        uint16 batchCount;
        mapping (uint8 => uint32) aggregatedVotes;
    }

    uint16 private _pollCount;
    mapping (uint16 => Poll) private polls;

    event SubmitBatch(bytes32 indexed batchId);
    event SubmitVote(uint256 indexed pollId, address indexed voter, uint8 vote);

    function createPoll(address relay, uint8 options)
        public
        returns (uint16 pollId)
    {
        pollId = _pollCount;
        _pollCount++;

        polls[pollId].relay = relay;
        polls[pollId].options = options;
    }

    function getCurrentBatchId(uint16 pollId)
        public
        view
        returns(bytes32 batchId)
    {
        batchId = keccak256(abi.encodePacked(pollId, polls[pollId].batchCount));
    }

    function submitBatch(uint16 pollId, uint8[] votes, bytes32[] sig_r, bytes32[] sig_s, uint8[] sig_v)
        public
    {
        require(msg.sender == polls[pollId].relay);
        require(votes.length == sig_r.length);
        require(votes.length == sig_s.length);
        require(votes.length == sig_v.length);

        uint256 len = votes.length;

        // Generate batch Id
        bytes32 batchId = getCurrentBatchId(pollId);

        // Initialize tallies
        uint16[256] memory voteTallies;

        // Recover address from each vote and add vote to tallies
        for (uint i=0; i<len; i++) {
            require(votes[i] < polls[pollId].options);

            bytes32 hash = keccak256(abi.encodePacked(pollId, votes[i]));
            address signer = ecrecover(hash, sig_v[i], sig_r[i], sig_s[i]);
            if (signer != address(0)) {
                voteTallies[votes[i]]++;

                emit SubmitVote(pollId, signer, votes[i]);
            }
        }

        // Add vote tallies to aggregated votes
        for (uint8 o=0; o<polls[pollId].options; o++) {
            polls[pollId].aggregatedVotes[o] += voteTallies[o];
        }

        polls[pollId].batchCount++;
        emit SubmitBatch(batchId);
    }

    function getVotingResults(uint16 pollId, uint8 option)
        public
        view
        returns(uint32)
    {
        return polls[pollId].aggregatedVotes[option];
    }

}
