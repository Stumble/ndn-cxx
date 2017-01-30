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

#include "validation-policy-regex.hpp"

#include <boost/lexical_cast.hpp>

namespace ndn {
namespace security {
namespace v2 {

void
ValidationPolicyRegex::addDataVerificationRule(unique_ptr<SecRuleRelative> rule)
{
  rule->isPositive() ? m_verifyPolicies.push_back(std::move(rule)) : m_mustFailVerify.push_back(std::move(rule));
}

void
ValidationPolicyRegex::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                   const ValidationContinuation& continueValidation)
{
  for (const auto& mustFailRule : m_mustFailVerify) {
    if (mustFailRule->satisfy(data)) {
      return state->fail({ValidationError::POLICY_ERROR, "Data " + data.getName().toUri() +
                          " matched negative rule " + boost::lexical_cast<std::string>(*mustFailRule)});
    }
  }

  for (const auto& rule : m_verifyPolicies) {
    if (rule->satisfy(data)) {
      BOOST_ASSERT(data.getSignature().hasKeyLocator() &&
                   data.getSignature().getKeyLocator().getType() == KeyLocator::KeyLocator_Name);

      const Name& locator = data.getSignature().getKeyLocator().getName();
      return continueValidation(make_shared<CertificateRequest>(Interest(locator)), state);
    }
  }

  return state->fail({ValidationError::POLICY_ERROR, "No policy found for data " + data.getName().toUri()});
}

void
ValidationPolicyRegex::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                   const ValidationContinuation& continueValidation)
{
  state->fail({ValidationError::POLICY_ERROR, "Policy doesn't support interest validation"});
}

} // namespace v2
} // namespace security
} // namespace ndn
