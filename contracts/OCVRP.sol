pragma solidity 0.4.25;

contract OCVRP {

    struct Batch {
        uint32 previousVoterCount;  // Defines the first voter number in this batch
        uint16 batchSize;           // Number of voters included in this batch
        bytes32 addressHash;        // Chained sha3 hash of all addresses
    }

    struct Poll {
        address relay;                              // Address of relaer
        bool valid;                                 // Validity flag
        uint256 votingStart;                        // Vote batches may be submitted in [votingStart, challengeStart)
        uint256 challengeStart;                     // Challenges may be submitted in [challengeStart, clearingStart)
        uint256 clearingStart;                      // Clearing may occur in [clearingStart, slashingStart)
        uint256 slashingStart;                      // Slashing may occur in [slashingStart, votingEndBlock)
        uint256 votingEnd;                          // Votes become final
        uint8 options;                              // Number of voting choices
        uint32 voterCount;                          // Current voter count
        uint16 batchCount;                          // Current batch count
        mapping (uint16 => Batch) batches;          // Bathes
        mapping (uint8 => uint32) aggregatedVotes;  // Vote aggregation
    }

    struct Challenge {
        uint16 batchId;      // Batch ID
        address voter;       // Voter address
        bool cleared;        // Cleared flag
    }

    uint16 private _pollCount;
    mapping (uint16 => Poll) private polls;
    mapping (uint16 => mapping (uint32 => Challenge)) private challenges;

    event SubmitBatch(bytes32 indexed batchId);
    event SubmitVote(uint256 indexed pollId, address indexed voter, uint8 vote);
    event SubmitChallenge(uint256 indexed pollId, address indexed voter);

    function createPoll(address relay,
            uint8 options,
            uint256 votingBlock,
            uint256 challengeBlock,
            uint256 clearingBlock,
            uint256 slashingBlock,
            uint256 endBlock)
        public
        returns (uint16 pollId)
    {
        pollId = _pollCount;
        _pollCount++;

        Poll storage poll = polls[pollId];

        poll.relay = relay;
        poll.options = options;
        poll.votingStart = votingBlock;
        poll.challengeStart = challengeBlock;
        poll.clearingStart = clearingBlock;
        poll.slashingStart = slashingBlock;
        poll.votingEnd = endBlock;
    }

    function submitBatch(uint16 pollId, uint8[] votes, bytes32[] sig_r, bytes32[] sig_s, uint8[] sig_v)
        public
    {
        Poll storage poll = polls[pollId];

        require(block.number >= poll.votingStart);
        require(block.number < poll.challengeStart);
        require(msg.sender == poll.relay);
        require(votes.length == sig_r.length);
        require(votes.length == sig_s.length);
        require(votes.length == sig_v.length);
        requireSufficientCollateral(pollId);

        uint16 len = uint16(votes.length);

        // Record a batch
        bytes32 addressHash = 0;
        poll.batches[poll.batchCount].previousVoterCount = poll.voterCount;
        poll.voterCount += len;

        // Initialize tallies
        uint16[256] memory voteTallies;

        // Recover address from each vote and add vote to tallies
        for (uint i=0; i<len; i++) {
            require(votes[i] < poll.options);

            // Voting message that was signed has following format:
            // 4 bytes:  pollId
            // 1 byte:   option voted
            bytes32 hash = keccak256(abi.encodePacked(pollId, votes[i]));
            address signer = ecrecover(hash, sig_v[i], sig_r[i], sig_s[i]);
            if (signer != address(0)) {
                voteTallies[votes[i]]++;

                emit SubmitVote(pollId, signer, votes[i]);

                // Calculate batch chained address hash
                addressHash = keccak256(abi.encodePacked(addressHash, signer));
            } else {
                revert();
            }
        }

        // Update batch hash
        poll.batches[poll.batchCount].addressHash = addressHash;
        poll.batches[poll.batchCount].batchSize = len;
        poll.batchCount++;

        // Add vote tallies to aggregated votes
        for (uint8 o=0; o<poll.options; o++) {
            poll.aggregatedVotes[o] += voteTallies[o];
        }
    }

    /**
    * Voter provides poll ID, batch ID, voter number, and voting receipt signed by relayer
    *
    */
    function challengeVote(uint16 pollId, uint16 batchId, uint32 voterNumber, bytes32 sig_r, bytes32 sig_s, uint8 sig_v)
        public
    {
        require(block.number >= polls[pollId].challengeStart);
        require(block.number < polls[pollId].clearingStart);

        // Verify voting receipt
        bytes32 receiptHash = keccak256(abi.encodePacked(msg.sender, pollId, batchId, voterNumber));
        address signedRelayer = ecrecover(receiptHash, sig_v, sig_r, sig_s);
        require(signedRelayer == polls[pollId].relay);

        // Receipt signature checked out. Record the challenge.
        challenges[pollId][voterNumber].batchId = batchId;
        challenges[pollId][voterNumber].voter = msg.sender;
    }

    /**
    * Relayer must prove that when he submitted the batch containing this vote,
    * he did not replace voter address. Voter signature guarantees validity of
    * vote message, so if address was included, it guarantees that vote was
    * correct. There is no need to challenge vote itself.
    *
    * Batch addresses must be submitted in the order they were submitted in the
    * batch to re-calculate chained batch address hash and prove that it did
    * not change and address is present at the expected position.
    *
    * @param pollId ID of poll challenged
    * @param voterNumber Vote number challenged
    * @param batchAddresses All voted addresses in the challenged batch
    *
    * TODO: Clear the whole batch in case if more than 1 address in the batch is challenged
    */
    function clearChallenge(uint16 pollId, uint32 voterNumber, address[] batchAddresses)
        public
    {
        require(block.number >= polls[pollId].clearingStart);
        require(block.number < polls[pollId].slashingStart);

        uint16 batchId = challenges[pollId][voterNumber].batchId;

        // Verify that batch size did not change
        uint256 len = batchAddresses.length;
        require(polls[pollId].batches[batchId].batchSize == len);

        // Verify chained batch address hash did not change
        // And voter address is present
        bytes32 addressHash = 0;
        bool voterPresent = false;
        for (uint i=0; i<len; i++) {
            addressHash = keccak256(abi.encodePacked(addressHash, batchAddresses[i]));
            if (batchAddresses[i] == challenges[pollId][voterNumber].voter)
                voterPresent = true;
        }
        require(voterPresent);
        require(polls[pollId].batches[batchId].addressHash == addressHash);

        // All checked out, the challenge is false
        challenges[pollId][voterNumber].cleared = true;
    }

    /**
    * In case if Relay did not provide sufficient proof to clear challenge,
    * the voter may slash Relay and receive their bonus.
    */
    function slashRelayer(uint16 pollId, uint32 voterNumber)
        public
    {
        require(block.number >= polls[pollId].slashingStart);
        require(block.number < polls[pollId].votingEnd);

        // Check if challenge was cleared
        require(!challenges[pollId][voterNumber].cleared);

        polls[pollId].valid = false;
        slashAndPayOut();
    }

    // TODO: Implement
    function requireSufficientCollateral(uint16 /*pollId*/)
        internal
        pure /*remove*/
        returns(bool)
    {
        return true;
    }

    /**
    * TODO: Implement collateral token deposit by the Relayer
    *
    */
    function depositCollatealToken(uint16 pollId)
        public
        view /*remove*/
    {
        Poll storage poll = polls[pollId];
        require(block.number < poll.votingStart);
        require(msg.sender == poll.relay);


    }

    /**
    * TODO: Implement collateral token withdraw by the Relayer
    *
    */
    function withdrawCollatealToken(uint16 pollId)
        public
        view /*remove*/
    {
        require(block.number >= polls[pollId].votingEnd);
        require(polls[pollId].valid);


    }

    /**
    * TODO: Implement collateral token payout
    *
    */
    function slashAndPayOut()
        internal
        pure /*remove*/
    {

    }

    function getVotingResults(uint16 pollId, uint8 option)
        public
        view
        returns(uint32)
    {
        return polls[pollId].aggregatedVotes[option];
    }

}
