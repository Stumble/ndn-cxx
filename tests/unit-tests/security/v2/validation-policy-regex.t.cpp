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

#include "security/v2/validation-policy-regex.hpp"

#include "boost-test.hpp"
#include "validator-fixture.hpp"

#include <boost/mpl/vector.hpp>

namespace ndn {
namespace security {
namespace v2 {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(V2)
BOOST_FIXTURE_TEST_SUITE(TestValidationPolicyRegex,
                         HierarchicalValidatorFixture<ValidationPolicyRegex>)

BOOST_AUTO_TEST_CASE(ValidateInterest)
{
  static_cast<ValidationPolicyRegex&>(validator.getPolicy()).addDataVerificationRule(
    make_unique<SecRuleRelative>("^(<>*)$", "^(<>*)<KEY><>$", ">=", "\\1", "\\1", true));

  Interest unsignedInterest("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest");
  Interest interest = unsignedInterest;
  VALIDATE_FAILURE(interest, "Policy doesn't accept Interest packets");

  interest = unsignedInterest;
  m_keyChain.sign(interest, signingWithSha256());
  VALIDATE_FAILURE(interest, "Policy doesn't accept Interest packets");

  interest = unsignedInterest;
  m_keyChain.sign(interest, signingByIdentity(identity));
  VALIDATE_FAILURE(interest, "Policy doesn't accept Interest packets");
}

BOOST_AUTO_TEST_SUITE(ValidateData)

BOOST_AUTO_TEST_CASE(NoRules)
{
  Data unsignedData("/Security/V2/ValidatorFixture/Sub1/Sub2/Data");

  Data data = unsignedData;
  VALIDATE_FAILURE(data, "Unsigned");

  data = unsignedData;
  m_keyChain.sign(data, signingWithSha256());
  VALIDATE_FAILURE(data, "Policy doesn't accept Sha256Digest signature");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(identity));
  VALIDATE_FAILURE(data, "Should fail, as no rules were specified");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(subIdentity));
  VALIDATE_FAILURE(data, "Should fail, as no rules were specified");
}

BOOST_AUTO_TEST_CASE(HierarchicalModel)
{
  static_cast<ValidationPolicyRegex&>(validator.getPolicy()).addDataVerificationRule(
    make_unique<SecRuleRelative>("^(<>*)$", "^(<>*)<KEY><>$", ">=", "\\1", "\\1", true));

  Data unsignedData("/Security/V2/ValidatorFixture/Sub1/Sub2/Data");

  Data data = unsignedData;
  VALIDATE_FAILURE(data, "Unsigned");

  data = unsignedData;
  m_keyChain.sign(data, signingWithSha256());
  VALIDATE_FAILURE(data, "Policy doesn't accept Sha256Digest signature");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(identity));
  VALIDATE_SUCCESS(data, "Should get accepted, as signed by the anchor");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(subIdentity));
  VALIDATE_SUCCESS(data, "Should get accepted, as signed by the policy-compliant cert");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(otherIdentity));
  VALIDATE_FAILURE(data, "Should fail, as signed by the policy-violating cert");

  data = unsignedData;
  m_keyChain.sign(data, signingByIdentity(subSelfSignedIdentity));
  VALIDATE_FAILURE(data, "Should fail, because subSelfSignedIdentity is not a trust anchor");
}

BOOST_AUTO_TEST_CASE(Fixed)
{
  static_cast<ValidationPolicyRegex&>(validator.getPolicy()).addDataVerificationRule(
    make_unique<SecRuleRelative>("^(<a><b>)$", "^<>*<KEY><>()$", "==", "\\1", "<a><b>\\1", true));

  Data data1("/a/b");
  m_keyChain.sign(data1, signingByIdentity(identity));
  VALIDATE_SUCCESS(data1, "Should get accepted, as data matches the validation rule");

  Data data2("/a/b/c");
  m_keyChain.sign(data2, signingByIdentity(identity));
  VALIDATE_FAILURE(data2, "Should fail, as data name doesn't match validation rules");
}

BOOST_AUTO_TEST_CASE(HierarchicalWithExclusion)
{
  static_cast<ValidationPolicyRegex&>(validator.getPolicy()).addDataVerificationRule(
    make_unique<SecRuleRelative>("^(<>*)$", "^(<>*)<KEY><>$", ">=", "\\1", "\\1", true));

  static_cast<ValidationPolicyRegex&>(validator.getPolicy()).addDataVerificationRule(
    make_unique<SecRuleRelative>("^(<>*<Excluded>)$", "^(<>*)<KEY><>$", ">=", "\\1", "\\1", false));

  Data data1("/Security/V2/ValidatorFixture/Sub1/Sub2/Other");
  m_keyChain.sign(data1, signingByIdentity(identity));
  VALIDATE_SUCCESS(data1, "Should get accepted, as data matches the validation rule");

  Data data2("/Security/V2/ValidatorFixture/Sub1/Sub2/Excluded");
  m_keyChain.sign(data2, signingByIdentity(identity));
  VALIDATE_FAILURE(data2, "Should fail, as data name matched negative rule");
}

BOOST_AUTO_TEST_SUITE_END() // ValidateData

BOOST_AUTO_TEST_SUITE_END() // TestValidator
BOOST_AUTO_TEST_SUITE_END() // V2
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace v2
} // namespace security
} // namespace ndn
