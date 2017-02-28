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

#include "validation-policy-config.hpp"
#include "validator.hpp"
#include "../../util/io.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/info_parser.hpp>

namespace ndn {
namespace security {
namespace v2 {

ValidationPolicyConfig::ValidationPolicyConfig()
  : m_shouldValidate(true)
  , m_hasBeenConfigured(false)
{
}

void
ValidationPolicyConfig::load(const std::string& filename)
{
  std::ifstream inputFile;
  inputFile.open(filename.c_str());
  if (!inputFile.good() || !inputFile.is_open()) {
    std::string msg = "Failed to read configuration file: ";
    msg += filename;
    BOOST_THROW_EXCEPTION(security::conf::Error(msg));
  }
  load(inputFile, filename);
  inputFile.close();
}

void
ValidationPolicyConfig::load(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}

void
ValidationPolicyConfig::load(std::istream& input, const std::string& filename)
{
  security::conf::ConfigSection tree;
  try {
    boost::property_tree::read_info(input, tree);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    std::stringstream msg;
    msg << "Failed to parse configuration file";
    msg << " " << filename;
    msg << " " << error.message() << " line " << error.line();
    BOOST_THROW_EXCEPTION(security::conf::Error(msg.str()));
  }

  load(tree, filename);
}

void
ValidationPolicyConfig::load(const security::conf::ConfigSection& configSection,
                             const std::string& filename)
{
  if (m_hasBeenConfigured) {
    BOOST_THROW_EXCEPTION(std::logic_error("ValidationPolicyConfig can be configured only once"));
  }
  m_hasBeenConfigured = true;

  BOOST_ASSERT(!filename.empty());

  if (configSection.begin() == configSection.end()) {
    std::string msg = "Error processing configuration file";
    msg += ": ";
    msg += filename;
    msg += " no data";
    BOOST_THROW_EXCEPTION(security::conf::Error(msg));
  }

  for (const auto& subSection : configSection) {
    const std::string& sectionName = subSection.first;
    const security::conf::ConfigSection& section = subSection.second;

    if (boost::iequals(sectionName, "rule")) {
      onConfigRule(section, filename);
    }
    else if (boost::iequals(sectionName, "trust-anchor")) {
      onConfigTrustAnchor(section, filename);
    }
    else {
      std::string msg = "Error processing configuration file";
      msg += " ";
      msg += filename;
      msg += " unrecognized section: " + sectionName;
      BOOST_THROW_EXCEPTION(security::conf::Error(msg));
    }
  }
}

void
ValidationPolicyConfig::onConfigRule(const security::conf::ConfigSection& configSection,
                                     const std::string& filename)
{
  using namespace ndn::security::conf;

  ConfigSection::const_iterator propertyIt = configSection.begin();

  // Get rule.id
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "id")) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <rule.id>"));
  }

  std::string ruleId = propertyIt->second.data();
  propertyIt++;

  // Get rule.for
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "for")) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <rule.for> in rule: " + ruleId));
  }

  std::string usage = propertyIt->second.data();
  propertyIt++;

  bool isForData = false;
  if (boost::iequals(usage, "data")) {
    isForData = true;
  }
  else if (boost::iequals(usage, "interest")) {
    isForData = false;
  }
  else {
    BOOST_THROW_EXCEPTION(security::conf::Error("Unrecognized <rule.for>: " + usage + " in rule: " + ruleId));
  }

  // Get rule.filter(s)
  std::vector<shared_ptr<Filter>> filters;
  for (; propertyIt != configSection.end(); propertyIt++) {
    if (!boost::iequals(propertyIt->first, "filter")) {
      if (boost::iequals(propertyIt->first, "checker")) {
        break;
      }
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <rule.filter> in rule: " + ruleId));
    }

    filters.push_back(FilterFactory::create(propertyIt->second));
    continue;
  }

  // Get rule.checker(s)
  std::vector<shared_ptr<Checker>> checkers;
  for (; propertyIt != configSection.end(); propertyIt++) {
    if (!boost::iequals(propertyIt->first, "checker")) {
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <rule.checker> in rule: " + ruleId));
    }

    checkers.push_back(CheckerFactory::create(propertyIt->second, filename));
    continue;
  }

  // Check other stuff
  if (propertyIt != configSection.end()) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Expecting the end of rule: " + ruleId));
  }

  if (checkers.empty()) {
    BOOST_THROW_EXCEPTION(security::conf::Error("No <rule.checker> is specified in rule: " + ruleId));
  }

  if (isForData) {
    auto rule = make_shared<conf::Rule>(ruleId);
    for (const auto& filter : filters) {
      rule->addFilter(filter);
    }
    for (const auto& checker : checkers) {
      rule->addChecker(checker);
    }

    m_dataRules.push_back(rule);
  }
  else {
    auto rule = make_shared<conf::Rule>(ruleId);;
    for (const auto& filter : filters) {
      rule->addFilter(filter);
    }
    for (const auto& checker : checkers) {
      rule->addChecker(checker);
    }

    m_interestRules.push_back(rule);
  }
}

void
ValidationPolicyConfig::onConfigTrustAnchor(const conf::ConfigSection& configSection,
                                            const std::string& filename)
{
  using namespace ndn::security::conf;
  using namespace boost::filesystem;

  ConfigSection::const_iterator propertyIt = configSection.begin();

  // Get trust-anchor.type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type")) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <trust-anchor.type>"));
  }

  std::string type = propertyIt->second.data();
  propertyIt++;

  if (boost::iequals(type, "file")) {
    // Get trust-anchor.file
    if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "file-name")) {
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <trust-anchor.file-name>"));
    }

    std::string file = propertyIt->second.data();
    propertyIt++;

    time::nanoseconds refresh = getRefreshPeriod(propertyIt, configSection.end());
    if (propertyIt != configSection.end()) {
      BOOST_THROW_EXCEPTION(security::conf::Error("Expect the end of trust-anchor!"));
    }

    m_validator->loadAnchor(filename, absolute(file, path(filename).parent_path()).string(),
                            refresh, false);
    return;
  }
  else if (boost::iequals(type, "base64")) {
    // Get trust-anchor.base64-string
    if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "base64-string"))
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <trust-anchor.base64-string>"));

    std::stringstream ss(propertyIt->second.data());
    propertyIt++;

    // Check other stuff
    if (propertyIt != configSection.end())
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting the end of trust-anchor"));

    auto idCert = io::load<Certificate>(ss);
    if (idCert != nullptr) {
      m_validator->loadAnchor("", std::move(*idCert));
    }
    else {
      BOOST_THROW_EXCEPTION(security::conf::Error("Cannot decode certificate from base64-string"));
    }

    return;
  }
  else if (boost::iequals(type, "dir")) {
    if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "dir"))
      BOOST_THROW_EXCEPTION(security::conf::Error("Expect <trust-anchor.dir>"));

    std::string dirString(propertyIt->second.data());
    propertyIt++;

    time::nanoseconds refresh = getRefreshPeriod(propertyIt, configSection.end());
    if (propertyIt != configSection.end()) {
      BOOST_THROW_EXCEPTION(security::conf::Error("Expecting the end of trust-anchor"));
    }

    path dirPath = absolute(dirString, path(filename).parent_path());
    m_validator->loadAnchor(dirString, dirPath.string(), refresh, true);
    return;
  }
  else if (boost::iequals(type, "any")) {
    m_shouldValidate = false;
  }
  else {
    BOOST_THROW_EXCEPTION(security::conf::Error("Unsupported trust-anchor.type: " + type));
  }
}

time::nanoseconds
ValidationPolicyConfig::getRefreshPeriod(conf::ConfigSection::const_iterator& it,
                                         const conf::ConfigSection::const_iterator& end)
{
  time::nanoseconds refresh = time::nanoseconds::max();
  if (it == end) {
    return refresh;
  }

  if (!boost::iequals(it->first, "refresh")) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Expecting <trust-anchor.refresh>"));
  }

  std::string inputString = it->second.data();
  ++it;

  char unit = inputString[inputString.size() - 1];
  std::string refreshString = inputString.substr(0, inputString.size() - 1);

  uint32_t refreshPeriod = 0;

  try {
    refreshPeriod = boost::lexical_cast<uint32_t>(refreshString);
  }
  catch (const boost::bad_lexical_cast&) {
    BOOST_THROW_EXCEPTION(security::conf::Error("Bad number: " + refreshString));
  }

  if (refreshPeriod == 0) {
    return getDefaultRefreshPeriod();
  }

  switch (unit) {
    case 'h':
      return time::duration_cast<time::nanoseconds>(time::hours(refreshPeriod));
    case 'm':
      return time::duration_cast<time::nanoseconds>(time::minutes(refreshPeriod));
    case 's':
      return time::duration_cast<time::nanoseconds>(time::seconds(refreshPeriod));
    default:
      BOOST_THROW_EXCEPTION(security::conf::Error(std::string("Wrong time unit: ") + unit));
  }
}

time::nanoseconds
ValidationPolicyConfig::getDefaultRefreshPeriod()
{
  return time::duration_cast<time::nanoseconds>(time::seconds(3600));
}

void
ValidationPolicyConfig::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                    const ValidationContinuation& continueValidation)
{
  if (!m_shouldValidate) {
    return continueValidation(nullptr, state);
  }

  if (!data.getSignature().hasKeyLocator()) {
    return state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Required key locator is missing"});
  }
  if (data.getSignature().getKeyLocator().getType() != KeyLocator::KeyLocator_Name) {
    return state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Key locator not Name"});
  }

  for (const auto& rule : m_dataRules) {
    if (rule->match(data)) {
      if (rule->check(data)) {
        const Name& locator = data.getSignature().getKeyLocator().getName();
        return continueValidation(make_shared<CertificateRequest>(Interest(locator)), state);
      }
      else {
        return state->fail({ValidationError::POLICY_ERROR, "Data `" + data.getName().toUri() + "` violates rule"});
      }
      break;
    }
  }

  return state->fail({ValidationError::POLICY_ERROR, "No rule matched for data `" + data.getName().toUri() + "`"});
}

void
ValidationPolicyConfig::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                    const ValidationContinuation& continueValidation)
{
  if (!m_shouldValidate) {
    return continueValidation(nullptr, state);
  }

  SignatureInfo info;
  try {
    info.wireDecode(interest.getName().at(signed_interest::POS_SIG_INFO).blockFromValue());
  }
  catch (const tlv::Error& e) {
    return state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Invalid signed interest (" +
                        std::string(e.what()) + ")"});
  }
  if (!info.hasKeyLocator()) {
    return state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Required key locator is missing"});
  }
  const KeyLocator& locator = info.getKeyLocator();
  if (locator.getType() != KeyLocator::KeyLocator_Name) {
    return state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Key locator not Name"});
  }

  state->fail({ValidationError::IMPLEMENTATION_ERROR, "Not implemented yet"});

  // // if (locator.getName().getPrefix(-2).isPrefixOf(interest.getName())) {
  // //   continueValidation(make_shared<CertificateRequest>(Interest(locator.getName())), state);
  // // }
  // // else {
  // //   state->fail({ValidationError::Code::INVALID_KEY_LOCATOR, "Interest signing policy violation for " +
  // //                interest.getName().toUri() + " by " + locator.getName().toUri()});
  // // }



  //   Name keyName = v1::IdentityCertificate::certificateNameToPublicKeyName(keyLocator.getName());

  //   bool isMatched = false;
  //   int8_t checkResult = -1;

  //   for (const auto& interestRule : m_interestRules) {
  //     if (interestRule->match(interest)) {
  //       isMatched = true;
  //       checkResult = interestRule->check(interest,
  //                                         bind(&ValidatorConfig::checkTimestamp, this, _1,
  //                                              keyName, onValidated, onValidationFailed),
  //                                         onValidationFailed);
  //       break;
  //     }
  //   }

  //   if (!isMatched)
  //     return onValidationFailed(interest.shared_from_this(), "No rule matched!");

  //   if (checkResult == 0) {
  //     checkSignature<Interest, OnInterestValidated, OnInterestValidationFailed>
  //       (interest, signature, nSteps,
  //        bind(&ValidatorConfig::checkTimestamp, this, _1,
  //             keyName, onValidated, onValidationFailed),
  //        onValidationFailed,
  //        nextSteps);
  //   }
  // }
}

} // namespace v2
} // namespace security
} // namespace ndn
