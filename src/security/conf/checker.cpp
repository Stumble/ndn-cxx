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

#include "checker.hpp"
#include "../verification-helpers.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace security {
namespace conf {

CustomizedChecker::CustomizedChecker(uint32_t sigType, shared_ptr<KeyLocatorChecker> keyLocatorChecker)
  : m_sigType(sigType)
  , m_keyLocatorChecker(keyLocatorChecker)
{
  switch (sigType) {
  case tlv::SignatureSha256WithRsa:
  case tlv::SignatureSha256WithEcdsa: {
    if (!static_cast<bool>(m_keyLocatorChecker))
      BOOST_THROW_EXCEPTION(Error("Strong signature requires KeyLocatorChecker"));
    return;
  }
  case tlv::DigestSha256:
    return;
  default:
    BOOST_THROW_EXCEPTION(Error("Unsupported signature type"));
  }
}

bool
CustomizedChecker::check(const Data& data)
{
  return check(data, data.getSignature());
}

bool
CustomizedChecker::check(const Interest& interest)
{
  try {
    const Name& interestName = interest.getName();
    Signature signature(interestName[command_interest::POS_SIG_INFO].blockFromValue(),
                        interestName[command_interest::POS_SIG_VALUE].blockFromValue());
    return check(interest, signature);
  }
  catch (const Signature::Error& e) {
    // Invalid signature
    return -1;
  }
  catch (const tlv::Error& e) {
    // Cannot decode signature related TLVs
    return -1;
  }
}

template<class Packet>
bool
CustomizedChecker::check(const Packet& packet, const Signature& signature)
{
  if (m_sigType != signature.getType()) {
    // Signature type does not match
    return false;
  }

  switch (signature.getType()) {
    case tlv::SignatureSha256WithRsa:
      // fallthrough
    case tlv::SignatureSha256WithEcdsa: {
      if (!signature.hasKeyLocator()) {
        // Missing KeyLocator in SignatureInfo
        return false;
      }
      break;
    }
    default: {
      // Unsupported signature type
      return false;
    }
  }

  return m_keyLocatorChecker->check(packet, signature.getKeyLocator());
}

HierarchicalChecker::HierarchicalChecker(uint32_t sigType)
  : CustomizedChecker(sigType,
                      make_shared<HyperKeyLocatorNameChecker>("^(<>*)$", "\\1",
                                                              "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                                              "\\1\\2",
                                                              KeyLocatorChecker::RELATION_IS_PREFIX_OF))
{
}

// FixedSignerChecker::FixedSignerChecker(uint32_t sigType,
//                                        const std::vector<shared_ptr<v1::IdentityCertificate>>& signers)
//   : m_sigType(sigType)
// {
//   for (std::vector<shared_ptr<v1::IdentityCertificate>>::const_iterator it = signers.begin();
//        it != signers.end(); it++)
//     m_signers[(*it)->getName().getPrefix(-1)] = (*it);

//   if (sigType != tlv::SignatureSha256WithRsa &&
//       sigType != tlv::SignatureSha256WithEcdsa) {
//     BOOST_THROW_EXCEPTION(Error("FixedSigner is only meaningful for strong signature type"));
//   }
// }

// int8_t
// FixedSignerChecker::check(const Data& data)
// {
//   return check(data, data.getSignature());
// }

// int8_t
// FixedSignerChecker::check(const Interest& interest)
// {
//   try {
//     const Name& interestName = interest.getName();
//     Signature signature(interestName[command_interest::POS_SIG_INFO].blockFromValue(),
//                         interestName[command_interest::POS_SIG_VALUE].blockFromValue());
//     return check(interest, signature);
//   }
//   catch (const Signature::Error& e) {
//     // Invalid signature
//     return -1;
//   }
//   catch (const tlv::Error& e) {
//     // Cannot decode signature related TLVs
//     return -1;
//   }
// }

// template<class Packet>
// int8_t
// FixedSignerChecker::check(const Packet& packet, const Signature& signature)
// {
//   if (m_sigType != signature.getType()) {
//     // Signature type does not match
//     return -1;
//   }

//   if (signature.getType() == tlv::DigestSha256) {
//     // FixedSigner does not allow Sha256 signature type
//     return -1;
//   }

//   try {
//     switch (signature.getType()) {
//       case tlv::SignatureSha256WithRsa:
//       case tlv::SignatureSha256WithEcdsa: {
//         if (!signature.hasKeyLocator()) {
//           // Missing KeyLocator in SignatureInfo
//           return -1;
//         }
//         break;
//       }

//       default: {
//         // Unsupported signature type
//         return -1;
//       }
//     }

//     const Name& keyLocatorName = signature.getKeyLocator().getName();

//     if (m_signers.find(keyLocatorName) == m_signers.end()) {
//       // Signer is not in the fixed signer list
//       return -1;
//     }

//     if (Validator::verifySignature(packet, signature,
//                                    m_signers[keyLocatorName]->getPublicKeyInfo())) {
//       return 1;
//     }
//     else {
//       // Signature cannot be validated
//       return -1;
//     }
//   }
//   catch (const KeyLocator::Error& e) {
//     // KeyLocator does not have name
//     return -1;
//   }
//   catch (const tlv::Error& e) {
//     // Cannot decode signature
//     return -1;
//   }
// }

shared_ptr<Checker>
CheckerFactory::create(const ConfigSection& configSection, const std::string& configFilename)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();

  // Get checker.type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type"))
    BOOST_THROW_EXCEPTION(Error("Expect <checker.type>"));

  std::string type = propertyIt->second.data();

  if (boost::iequals(type, "customized"))
    return createCustomizedChecker(configSection, configFilename);
  else if (boost::iequals(type, "hierarchical"))
    return createHierarchicalChecker(configSection, configFilename);
  // else if (boost::iequals(type, "fixed-signer"))
  //   return createFixedSignerChecker(configSection, configFilename);
  else
    BOOST_THROW_EXCEPTION(Error("Unsupported checker type: " + type));
}

shared_ptr<Checker>
CheckerFactory::createCustomizedChecker(const ConfigSection& configSection,
                                        const std::string& configFilename)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  // Get checker.sig-type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "sig-type"))
    BOOST_THROW_EXCEPTION(Error("Expect <checker.sig-type>"));

  std::string sigType = propertyIt->second.data();
  propertyIt++;

  // Get checker.key-locator
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "key-locator"))
    BOOST_THROW_EXCEPTION(Error("Expect <checker.key-locator>"));

  shared_ptr<KeyLocatorChecker> keyLocatorChecker =
    KeyLocatorCheckerFactory::create(propertyIt->second, configFilename);
  propertyIt++;

  if (propertyIt != configSection.end())
    BOOST_THROW_EXCEPTION(Error("Expect the end of checker"));

  return make_shared<CustomizedChecker>(getSigType(sigType), keyLocatorChecker);
}

shared_ptr<Checker>
CheckerFactory::createHierarchicalChecker(const ConfigSection& configSection,
                                          const std::string& configFilename)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  // Get checker.sig-type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "sig-type"))
    BOOST_THROW_EXCEPTION(Error("Expect <checker.sig-type>"));

  std::string sigType = propertyIt->second.data();
  propertyIt++;

  if (propertyIt != configSection.end())
    BOOST_THROW_EXCEPTION(Error("Expect the end of checker"));

  return make_shared<HierarchicalChecker>(getSigType(sigType));
}

// shared_ptr<Checker>
// CheckerFactory::createFixedSignerChecker(const ConfigSection& configSection,
//                                          const std::string& configFilename)
// {
//   ConfigSection::const_iterator propertyIt = configSection.begin();
//   propertyIt++;

//   // Get checker.sig-type
//   if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "sig-type"))
//     BOOST_THROW_EXCEPTION(Error("Expect <checker.sig-type>"));

//   std::string sigType = propertyIt->second.data();
//   propertyIt++;

//   std::vector<shared_ptr<v1::IdentityCertificate>> signers;
//   for (; propertyIt != configSection.end(); propertyIt++) {
//     if (!boost::iequals(propertyIt->first, "signer"))
//       BOOST_THROW_EXCEPTION(Error("Expect <checker.signer> but get <checker." +
//                                   propertyIt->first + ">"));

//     signers.push_back(getSigner(propertyIt->second, configFilename));
//   }

//   if (propertyIt != configSection.end())
//     BOOST_THROW_EXCEPTION(Error("Expect the end of checker"));

//   return shared_ptr<FixedSignerChecker>(new FixedSignerChecker(getSigType(sigType),
//                                                                signers));
// }

// shared_ptr<v1::IdentityCertificate>
// CheckerFactory::getSigner(const ConfigSection& configSection, const std::string& configFilename)
// {
//   using namespace boost::filesystem;

//   ConfigSection::const_iterator propertyIt = configSection.begin();

//   // Get checker.signer.type
//   if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type"))
//     BOOST_THROW_EXCEPTION(Error("Expect <checker.signer.type>"));

//   std::string type = propertyIt->second.data();
//   propertyIt++;

//   if (boost::iequals(type, "file")) {
//     // Get checker.signer.file-name
//     if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "file-name"))
//       BOOST_THROW_EXCEPTION(Error("Expect <checker.signer.file-name>"));

//     path certfilePath = absolute(propertyIt->second.data(),
//                                  path(configFilename).parent_path());
//     propertyIt++;

//     if (propertyIt != configSection.end())
//       BOOST_THROW_EXCEPTION(Error("Expect the end of checker.signer"));

//     shared_ptr<v1::IdentityCertificate> idCert
//       = io::load<v1::IdentityCertificate>(certfilePath.c_str());

//     if (static_cast<bool>(idCert))
//       return idCert;
//     else
//       BOOST_THROW_EXCEPTION(Error("Cannot read certificate from file: " +
//                                   certfilePath.native()));
//   }
//   else if (boost::iequals(type, "base64")) {
//     // Get checker.signer.base64-string
//     if (propertyIt == configSection.end() ||
//         !boost::iequals(propertyIt->first, "base64-string"))
//       BOOST_THROW_EXCEPTION(Error("Expect <checker.signer.base64-string>"));

//     std::stringstream ss(propertyIt->second.data());
//     propertyIt++;

//     if (propertyIt != configSection.end())
//       BOOST_THROW_EXCEPTION(Error("Expect the end of checker.signer"));

//     shared_ptr<v1::IdentityCertificate> idCert = io::load<v1::IdentityCertificate>(ss);

//     if (static_cast<bool>(idCert))
//       return idCert;
//     else
//       BOOST_THROW_EXCEPTION(Error("Cannot decode certificate from string"));
//   }
//   else
//     BOOST_THROW_EXCEPTION(Error("Unsupported checker.signer type: " + type));
// }

uint32_t
CheckerFactory::getSigType(const std::string& sigType)
{
  if (boost::iequals(sigType, "rsa-sha256"))
    return tlv::SignatureSha256WithRsa;
  else if (boost::iequals(sigType, "ecdsa-sha256"))
    return tlv::SignatureSha256WithEcdsa;
  else if (boost::iequals(sigType, "sha256"))
    return tlv::DigestSha256;
  else
    BOOST_THROW_EXCEPTION(Error("Unsupported signature type"));
}

} // namespace conf
} // namespace security
} // namespace ndn
