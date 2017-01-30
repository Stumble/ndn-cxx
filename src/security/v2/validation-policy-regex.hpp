/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2017 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#ifndef NDN_SECURITY_V2_VALIDATION_POLICY_REGEX_HPP
#define NDN_SECURITY_V2_VALIDATION_POLICY_REGEX_HPP

#include "validator.hpp"
#include "../sec-rule-relative.hpp"
#include "../../util/regex.hpp"

namespace ndn {
namespace security {
namespace v2 {

class ValidationPolicyRegex : public ValidationPolicy
{
public:
  /**
   * @brief Add a rule for data verification.
   *
   * @param rule The verification rule
   */
  void
  addDataVerificationRule(unique_ptr<SecRuleRelative> rule);

private:
  void
  checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

  void
  checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

private:
  std::vector<unique_ptr<SecRuleRelative>> m_mustFailVerify;
  std::vector<unique_ptr<SecRuleRelative>> m_verifyPolicies;
};

} // namespace v2
} // namespace security

using security::v2::ValidationPolicyRegex;

} // namespace ndn

#endif // NDN_SECURITY_V2_VALIDATION_POLICY_REGEX_HPP
