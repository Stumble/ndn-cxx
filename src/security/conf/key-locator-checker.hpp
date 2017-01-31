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

#ifndef NDN_SECURITY_CONF_KEY_LOCATOR_CHECKER_HPP
#define NDN_SECURITY_CONF_KEY_LOCATOR_CHECKER_HPP

#include "common.hpp"
#include "../../interest.hpp"
#include "../../data.hpp"
#include "../../util/regex.hpp"

namespace ndn {
namespace security {
namespace conf {

/**
 * @brief KeyLocatorChecker is one of the classes used by ValidationPolicyConfig.
 *
 * The ValidationPolicyConfig class consists of a set of rules.
 * The KeyLocatorChecker class is part of a rule and is used to check if the KeyLocator field of a
 * packet satisfy the requirements.
 */
class KeyLocatorChecker : noncopyable
{
public:
  enum Relation {
    RELATION_EQUAL,
    RELATION_IS_PREFIX_OF,
    RELATION_IS_STRICT_PREFIX_OF
  };

  virtual
  ~KeyLocatorChecker() = default;

  bool
  check(const Data& data, const KeyLocator& keyLocator);

  bool
  check(const Interest& interest, const KeyLocator& keyLocator);

protected:
  virtual bool
  check(const Name& packetName, const KeyLocator& keyLocator) = 0;

  bool
  checkRelation(const Relation& relation, const Name& name1, const Name& name2);
};

class RelationKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  RelationKeyLocatorNameChecker(const Name& name, const KeyLocatorChecker::Relation& relation);

protected:
  bool
  check(const Name& packetName, const KeyLocator& keyLocator) override;

private:
  Name m_name;
  KeyLocatorChecker::Relation m_relation;
};

class RegexKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  explicit
  RegexKeyLocatorNameChecker(const Regex& regex);

protected:
  bool
  check(const Name& packetName, const KeyLocator& keyLocator) override;

private:
  Regex m_regex;
};

class HyperKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  HyperKeyLocatorNameChecker(const std::string& pExpr, const std::string pExpand,
                             const std::string& kExpr, const std::string kExpand,
                             const Relation& hyperRelation);

protected:
  bool
  check(const Name& packetName, const KeyLocator& keyLocator) override;

private:
  shared_ptr<Regex> m_hyperPRegex;
  shared_ptr<Regex> m_hyperKRegex;
  Relation m_hyperRelation;
};

class KeyLocatorCheckerFactory
{
public:
  static shared_ptr<KeyLocatorChecker>
  create(const ConfigSection& configSection, const std::string& filename);

private:
  static shared_ptr<KeyLocatorChecker>
  createKeyLocatorNameChecker(const ConfigSection& configSection,
                              const std::string& filename);
};

} // namespace conf
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_CONF_KEY_LOCATOR_CHECKER_HPP
