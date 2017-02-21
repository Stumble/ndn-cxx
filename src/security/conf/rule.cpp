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

#include "rule.hpp"

namespace ndn {
namespace security {
namespace conf {

Rule::Rule(const std::string& id)
  : m_id(id)
{
}

void
Rule::addFilter(const shared_ptr<Filter>& filter)
{
  m_filters.push_back(filter);
}

void
Rule::addChecker(const shared_ptr<Checker>& checker)
{
  m_checkers.push_back(checker);
}

template<class Packet>
bool
Rule::match(const Packet& packet) const
{
  if (m_filters.empty()) {
    return true;
  }

  for (const auto& filter : m_filters) {
    if (!filter->match(packet)) {
      return false;
    }
  }

  return true;
}

template
bool
Rule::match(const Data&) const;

template<class Packet>
bool
Rule::check(const Packet& packet) const
{
  bool hasPendingResult = false;
  for (const auto& checker : m_checkers) {
    bool result = checker->check(packet);
    if (!result) {
      return result;
    }
    hasPendingResult = true;
  }

  return hasPendingResult;
}

template
bool
Rule::check(const Data&) const;

} // namespace conf
} // namespace security
} // namespace ndn
