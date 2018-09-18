/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
#define IROHA_PROTO_TRANSACTION_VALIDATOR_HPP

#include "backend/protobuf/util.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "interfaces/permissions.hpp"
#include "transaction.pb.h"
#include "validators/abstract_validator.hpp"

namespace shared_model {
  namespace validation {

    class ProtoTransactionValidator
        : public AbstractValidator<iroha::protocol::Transaction> {
     public:
      Answer validate(
          const iroha::protocol::Transaction &transaction) const override {
        Answer answer;
        std::string tx_reason_name = "Transaction ";
        ReasonsGroupType tx_reason(tx_reason_name, GroupedReasons());

        for (const auto &command :
             transaction.payload().reduced_payload().commands()) {
          if (command.command_case()
              == iroha::protocol::Command::COMMAND_NOT_SET) {
            tx_reason.second.emplace_back("Undefined command is found");
            answer.addReason(std::move(tx_reason));
            break;
          } else if (command.command_case()
                     == iroha::protocol::Command::kCreateRole) {
            const auto &cr = command.create_role();
            bool all_permissions_valid = std::all_of(
                cr.permissions().begin(),
                cr.permissions().end(),
                [](const auto &perm) {
                  return interface::permissions::isValid(
                      static_cast<interface::permissions::Role>(perm));
                });
            if (not all_permissions_valid) {
              tx_reason.second.emplace_back("Undefined command is found");
              answer.addReason(std::move(tx_reason));
              break;
            }
          }
        }
        return answer;
      };
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_VALIDATOR_HPP
