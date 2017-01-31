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

#ifndef NDN_SECURITY_V2_VALIDATION_POLICY_CONFIG_HPP
#define NDN_SECURITY_V2_VALIDATION_POLICY_CONFIG_HPP

#include "validation-policy.hpp"
#include "../conf/rule.hpp"
#include "../conf/common.hpp"

namespace ndn {
namespace security {
namespace v2 {

/**
 * @brief The validator which can be set up via a configuration file.
 */
class ValidationPolicyConfig : public ValidationPolicy
{
public:
  ValidationPolicyConfig();

  void
  load(const std::string& filename);

  void
  load(const std::string& input, const std::string& filename);

  void
  load(std::istream& input, const std::string& filename);

  void
  load(const security::conf::ConfigSection& configSection,
       const std::string& filename);

protected:
  void
  checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

  void
  checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
              const ValidationContinuation& continueValidation) override;

private:
  void
  onConfigRule(const security::conf::ConfigSection& section,
               const std::string& filename);

  void
  onConfigTrustAnchor(const security::conf::ConfigSection& section,
                      const std::string& filename);

  time::nanoseconds
  getRefreshPeriod(conf::ConfigSection::const_iterator& it, const conf::ConfigSection::const_iterator& end);

  time::nanoseconds
  getDefaultRefreshPeriod();

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /**
   * @brief gives whether validation should be preformed
   *
   * If false, no validation occurs, and any packet is considered validated immediately.
   */
  bool m_shouldValidate;
  bool m_hasBeenConfigured;

  std::vector<shared_ptr<conf::Rule>> m_interestRules;
  std::vector<shared_ptr<conf::Rule>> m_dataRules;
};

} // namespace v2
} // namespace security

using security::v2::ValidationPolicyConfig;

} // namespace ndn

#endif // NDN_SECURITY_V2_VALIDATION_POLICY_CONFIG_HPP
