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

#include "sec-rule-relative.hpp"

#include "signature-sha256-with-rsa.hpp"
#include "security-common.hpp"

#include "util/logger.hpp"

namespace ndn {
namespace security {

NDN_LOG_INIT(ndn.security.SecRuleRelative);

SecRuleRelative::SecRuleRelative(const std::string& dataRegex, const std::string& signerRegex,
                                 const std::string& op,
                                 const std::string& dataExpand, const std::string& signerExpand,
                                 bool isPositive)
  : SecRule(isPositive),
    m_dataRegex(dataRegex),
    m_signerRegex(signerRegex),
    m_op(op),
    m_dataExpand(dataExpand),
    m_signerExpand(signerExpand),
    m_dataNameRegex(dataRegex, dataExpand),
    m_signerNameRegex(signerRegex, signerExpand)
{
  if (op != ">" && op != ">=" && op != "==") {
    BOOST_THROW_EXCEPTION(Error("Unrecognized operator `" + op + "`"));
  }
}

bool
SecRuleRelative::satisfy(const Data& data) const
{
  Name dataName = data.getName();
  try {
    if (!data.getSignature().hasKeyLocator())
      return false;

    const KeyLocator& keyLocator = data.getSignature().getKeyLocator();
    if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
      return false;

    const Name& signerName = keyLocator.getName();
    return satisfy(dataName, signerName);
  }
  catch (const tlv::Error& e) {
    NDN_LOG_TRACE("TLV Error: " << e.what());
    return false;
  }
  catch (const RegexMatcher::Error& e) {
    NDN_LOG_TRACE("RegexMatcher Error: " << e.what());
    return false;
  }
}

bool
SecRuleRelative::satisfy(const Name& dataName, const Name& signerName) const
{
  if (!m_dataNameRegex.match(dataName) || !m_signerNameRegex.match(signerName)) {
    return false;
  }
  NDN_LOG_TRACE("Matched data and signer name for " << dataName << " (signed by " << signerName << ")");

  return compare(m_dataNameRegex.expand(), m_signerNameRegex.expand());
}

bool
SecRuleRelative::matchDataName(const Data& data) const
{
  return m_dataNameRegex.match(data.getName());
}

bool
SecRuleRelative::matchSignerName(const Data& data) const
{
  try {
    if (!data.getSignature().hasKeyLocator())
      return false;

    const KeyLocator& keyLocator = data.getSignature().getKeyLocator();
    if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
      return false;

    const Name& signerName = keyLocator.getName();
    return m_signerNameRegex.match(signerName);
  }
  catch (const tlv::Error& e) {
    return false;
  }
  catch (const RegexMatcher::Error& e) {
    return false;
  }
}

bool
SecRuleRelative::compare(const Name& dataName, const Name& signerName) const
{
  NDN_LOG_TRACE("Comparing " << dataName << " " << m_op << " " << signerName);

  if (m_op == "==") {
    return dataName == signerName;
  }
  else if (m_op == ">=") {
    return signerName.isPrefixOf(dataName);
  }
  else if (m_op == ">") {
    return dataName.size() > signerName.size() && signerName.isPrefixOf(dataName);
  }
  else {
    return false;
  }
}

std::ostream&
operator<<(std::ostream& os, const SecRuleRelative& rule)
{
  return os << (rule.isPositive() ? "+ " : "- ")
            << rule.m_dataRegex << " (" << rule.m_dataExpand << ")"
            << " " << rule.m_op << " "
            << rule.m_signerRegex << " (" << rule.m_signerExpand << ")";
}

} // namespace security
} // namespace ndn
