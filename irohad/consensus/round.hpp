/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROUND_HPP
#define IROHA_ROUND_HPP

#include <cstdint>
#include <utility>

#include <boost/functional/hash.hpp>

namespace shared_model {
  namespace interface {
    class Proposal;
    class Block;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace consensus {

    /**
     * Type of round indexing by blocks
     */
    using BlockRoundType = uint64_t;

    /**
     * Type of round indexing by reject before new block commit
     */
    using RejectRoundType = uint32_t;

    /**
     * Type of proposal round
     */
    struct Round {
      BlockRoundType block_round;
      RejectRoundType reject_round;

      bool operator<(const Round &rhs) const {
        return std::tie(block_round, reject_round)
            < std::tie(rhs.block_round, rhs.reject_round);
      }

      bool operator==(const Round &rhs) const {
        return std::tie(block_round, reject_round)
            == std::tie(rhs.block_round, rhs.reject_round);
      }

      bool operator!=(const Round &rhs) const {
        return not (*this == rhs);
      }
    };

    /**
     * Class provides hash function for Round
     */
    class RoundTypeHasher {
     public:
      std::size_t operator()(const consensus::Round &val) const {
        size_t seed = 0;
        boost::hash_combine(seed, val.block_round);
        boost::hash_combine(seed, val.reject_round);
        return seed;
      }
    };

    /**
     * Type of proposal and round this proposal was voted for in
     */
    using ProposalWithRound =
        std::pair<std::shared_ptr<shared_model::interface::Proposal>,
                  std::shared_ptr<Round>>;

    /**
     * Type of block and round this block was voted for in
     */
    using BlockWithRound =
        std::pair<std::shared_ptr<shared_model::interface::Block>,
                  std::shared_ptr<Round>>;

  }  // namespace consensus
}  // namespace iroha

#endif  // IROHA_ROUND_HPP
