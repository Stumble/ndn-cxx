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

#ifndef NDN_SECURITY_CONF_FILTER_HPP
#define NDN_SECURITY_CONF_FILTER_HPP

#include "common.hpp"
#include "../../interest.hpp"
#include "../../data.hpp"
#include "../../util/regex.hpp"

namespace ndn {
namespace security {
namespace conf {

/**
 * @brief Filter is one of the classes used by ValidatorConfig.
 *
 * The ValidatorConfig class consists of a set of rules.
 * The Filter class is a part of a rule and is used to match packet.
 * Matched packets will be checked against the checkers defined in the rule.
 */
class Filter : noncopyable
{
public:
  virtual
  ~Filter() = default;

  bool
  match(const Data& data);

  bool
  match(const Interest& interest);

protected:
  virtual bool
  matchName(const Name& name) = 0;
};

class RelationNameFilter : public Filter
{
public:
  enum Relation
  {
    RELATION_EQUAL,
    RELATION_IS_PREFIX_OF,
    RELATION_IS_STRICT_PREFIX_OF
  };

  RelationNameFilter(const Name& name, Relation relation);

protected:
  bool
  matchName(const Name& name) override;

private:
  Name m_name;
  Relation m_relation;
};

class RegexNameFilter : public Filter
{
public:
  explicit
  RegexNameFilter(const Regex& regex);

protected:
  bool
  matchName(const Name& name) override;

private:
  Regex m_regex;
};

class FilterFactory
{
public:
  static shared_ptr<Filter>
  create(const ConfigSection& configSection);

private:
  static shared_ptr<Filter>
  createNameFilter(const ConfigSection& configSection);
};

} // namespace conf
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_CONF_FILTER_HPP
