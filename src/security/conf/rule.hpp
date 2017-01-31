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

#ifndef NDN_SECURITY_CONF_RULE_HPP
#define NDN_SECURITY_CONF_RULE_HPP

#include "filter.hpp"
#include "checker.hpp"

namespace ndn {
namespace security {
namespace conf {

class Rule : noncopyable
{
public:
  explicit
  Rule(const std::string& id);

  virtual
  ~Rule() = default;

  const std::string&
  getId()
  {
    return m_id;
  }

  void
  addFilter(const shared_ptr<Filter>& filter);

  void
  addChecker(const shared_ptr<Checker>& checker);

  template<class Packet>
  bool
  match(const Packet& packet) const;

  /**
   * @brief check if packet satisfies rule's condition
   *
   * @param packet The packet
   * @return false packet violates the rule
   *         true  packet satisfies the rule, further validation is needed
   */
  template<class Packet>
  bool
  check(const Packet& packet) const;

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::string m_id;
  std::vector<shared_ptr<Filter>> m_filters;
  std::vector<shared_ptr<Checker>> m_checkers;
};

} // namespace conf
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_CONF_RULE_HPP
