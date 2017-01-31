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

#ifndef NDN_SECURITY_VALIDATOR_NULL_HPP
#define NDN_SECURITY_VALIDATOR_NULL_HPP

#include "v2/validator.hpp"
#include "v2/validation-policy-accept-all.hpp"
#include "v2/certificate-fetcher-offline.hpp"

namespace ndn {
namespace security {
namespace v2 {

/**
 * @brief Validator with "accept-all" policy and offline certificate fetcher
 */
class ValidatorNull : public Validator
{
public:
  ValidatorNull()
    : Validator(make_unique<ValidationPolicyAcceptAll>(), make_unique<CertificateFetcherOffline>())
  {
  }
};

} // namespace v2

using v2::ValidatorNull;

} // namespace security
} // namespace ndn


#endif // NDN_SECURITY_VALIDATOR_NULL_HPP
