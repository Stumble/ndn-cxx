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

#include "security/digest-sha256.hpp"
#include "security/verification-helpers.hpp"
#include "util/string-helper.hpp"
#include "util/crypto.hpp"

#include "identity-management-fixture.hpp"
#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace tests {

BOOST_AUTO_TEST_SUITE(Security)
BOOST_FIXTURE_TEST_SUITE(TestDigestSha256, ndn::tests::IdentityManagementFixture)

const std::string DIGEST = "a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4";

BOOST_AUTO_TEST_CASE(Sha256)
{
  char content[6] = "1234\n";
  ConstBufferPtr buf = crypto::computeSha256Digest(reinterpret_cast<uint8_t*>(content), 5);

  BOOST_CHECK_EQUAL(toHex(buf->buf(), buf->size(), false), DIGEST);
}

BOOST_AUTO_TEST_CASE(DataSignature)
{
  Data testData("/TestSignatureSha/Basic");
  m_keyChain.sign(testData, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));

  BOOST_CHECK(verifyDigest(testData, DigestAlgorithm::SHA256));
  BOOST_CHECK_THROW(testData.getSignature().getKeyLocator(), ndn::SignatureInfo::Error);

  testData.setSignature(Signature(testData.getSignature().getInfo(),
                                  Block(tlv::SignatureValue, fromHex(DIGEST))));
  BOOST_CHECK(!verifyDigest(testData, DigestAlgorithm::SHA256));
}

BOOST_AUTO_TEST_CASE(InterestSignature)
{
  Interest testInterest("/SecurityTestDigestSha256/InterestSignature/Interest1");
  m_keyChain.sign(testInterest, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
  BOOST_CHECK(verifyDigest(testInterest, DigestAlgorithm::SHA256));

  Name invalidSignatureName = testInterest.getName().getPrefix(-1);
  Block invalidSignature(tlv::SignatureValue, fromHex(DIGEST));
  invalidSignature.encode();
  invalidSignatureName.append(invalidSignature);
  testInterest = Interest(invalidSignatureName);
  BOOST_CHECK(!verifyDigest(testInterest, DigestAlgorithm::SHA256));
}

BOOST_AUTO_TEST_SUITE_END() // TestDigestSha256
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace security
} // namespace ndn
