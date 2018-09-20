/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_FACTORY_HPP
#define IROHA_PROPOSAL_FACTORY_HPP

#include <memory>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;

    /**
     * ProposalFactory creates proposal
     */
    class ProposalFactory {
     public:
      template <typename T>
      using FactoryResult = iroha::expected::Result<T, std::string>;

      virtual FactoryResult<std::unique_ptr<Proposal>> createProposal(
          types::HeightType height,
          types::TimestampType created_time,
          boost::any_range<Transaction, boost::forward_traversal_tag>
              transactions) = 0;

      virtual ~ProposalFactory() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_PROPOSAL_FACTORY_HPP
