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

#ifndef NDN_SECURITY_SEC_RULE_RELATIVE_HPP
#define NDN_SECURITY_SEC_RULE_RELATIVE_HPP

#include "sec-rule.hpp"
#include "../util/regex.hpp"

namespace ndn {
namespace security {

class SecRuleRelative : public SecRule
{
public:
  class Error : public SecRule::Error
  {
  public:
    using SecRule::Error::Error;
  };

  SecRuleRelative(const std::string& dataRegex, const std::string& signerRegex,
                  const std::string& op,
                  const std::string& dataExpand, const std::string& signerExpand,
                  bool isPositive);

  bool
  matchDataName(const Data& data) const override;

  bool
  matchSignerName(const Data& data) const override;

  bool
  satisfy(const Data& data) const override;

  bool
  satisfy(const Name& dataName, const Name& signerName) const override;

private:
  bool
  compare(const Name& dataName, const Name& signerName) const;

private:
  const std::string m_dataRegex;
  const std::string m_signerRegex;
  const std::string m_op;
  const std::string m_dataExpand;
  const std::string m_signerExpand;

  mutable Regex m_dataNameRegex;
  mutable Regex m_signerNameRegex;

  friend std::ostream&
  operator<<(std::ostream& os, const SecRuleRelative& rule);
};

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_SEC_RULE_RELATIVE_HPP
