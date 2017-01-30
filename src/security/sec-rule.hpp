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

#ifndef NDN_SECURITY_SEC_RULE_HPP
#define NDN_SECURITY_SEC_RULE_HPP

#include "../common.hpp"
#include "../data.hpp"

namespace ndn {
namespace security {

class SecRule : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  explicit
  SecRule(bool isPositive)
    : m_isPositive(isPositive)
  {
  }

  virtual
  ~SecRule() = default;

  virtual bool
  matchDataName(const Data& data) const = 0;

  virtual bool
  matchSignerName(const Data& data) const = 0;

  virtual bool
  satisfy(const Data& data) const = 0;

  virtual bool
  satisfy(const Name& dataName, const Name& signerName) const = 0;

  bool
  isPositive() const
  {
    return m_isPositive;
  }

protected:
  bool m_isPositive;
};

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_SEC_RULE_HPP
