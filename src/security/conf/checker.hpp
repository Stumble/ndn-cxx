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

#ifndef NDN_SECURITY_CONF_CHECKER_HPP
#define NDN_SECURITY_CONF_CHECKER_HPP

#include "common.hpp"

#include "key-locator-checker.hpp"

namespace ndn {
namespace security {
namespace conf {

class Checker : noncopyable
{
public:
  virtual
  ~Checker() = default;

  /**
   * @brief check if data satisfies condition defined in the specific checker implementation
   *
   * @param data Data packet
   * @retval false data is immediately invalid
   * @retval true  further signature verification is needed.
   */
  virtual bool
  check(const Data& data) = 0;

  /**
   * @brief check if interest satisfies condition defined in the specific checker implementation
   *
   * @param interest Interest packet
   * @retval false interest is immediately invalid
   * @retval true  further signature verification is needed.
   */
  virtual bool
  check(const Interest& interest) = 0;
};

class CustomizedChecker : public Checker
{
public:
  CustomizedChecker(uint32_t sigType, shared_ptr<KeyLocatorChecker> keyLocatorChecker);

  bool
  check(const Data& data) override;

  bool
  check(const Interest& interest) override;

private:
  template<class Packet>
  bool
  check(const Packet& packet, const Signature& signature);

private:
  uint32_t m_sigType;
  shared_ptr<KeyLocatorChecker> m_keyLocatorChecker;
};

class HierarchicalChecker : public CustomizedChecker
{
public:
  explicit
  HierarchicalChecker(uint32_t sigType);
};

// class FixedSignerChecker : public Checker
// {
// public:
//   FixedSignerChecker(uint32_t sigType,
//                      const std::vector<shared_ptr<v1::IdentityCertificate>>& signers);

//   int8_t
//   check(const Data& data) override;

//   int8_t
//   check(const Interest& interest) override;

// private:
//   template<class Packet>
//   int8_t
//   check(const Packet& packet, const Signature& signature);

// private:
//   // typedef std::map<Name, shared_ptr<v1::IdentityCertificate>> SignerList;
//   uint32_t m_sigType;
//   SignerList m_signers;
// };

class CheckerFactory
{
public:
  /**
   * @brief create a checker from configuration file.
   *
   * @param configSection The section containing the definition of checker.
   * @param configFilename The configuration file name.
   * @return a shared pointer to the created checker.
   */
  static shared_ptr<Checker>
  create(const ConfigSection& configSection, const std::string& configFilename);

private:
  static shared_ptr<Checker>
  createCustomizedChecker(const ConfigSection& configSection, const std::string& configFilename);

  static shared_ptr<Checker>
  createHierarchicalChecker(const ConfigSection& configSection, const std::string& configFilename);

  // static shared_ptr<Checker>
  // createFixedSignerChecker(const ConfigSection& configSection, const std::string& configFilename);

  // static shared_ptr<v1::IdentityCertificate>
  // getSigner(const ConfigSection& configSection, const std::string& configFilename);

  static uint32_t
  getSigType(const std::string& sigType);
};

} // namespace conf
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_CONF_CHECKER_HPP
