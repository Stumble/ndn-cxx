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

#include "validation-policy-command-interest.hpp"
#include "../pib/key.hpp"

#include <boost/lexical_cast.hpp>

namespace ndn {
namespace security {
namespace v2 {

ValidationPolicyCommandInterest::ValidationPolicyCommandInterest(unique_ptr<ValidationPolicy> inner,
                                                                 const Options& options)
  : m_inner(std::move(inner))
  , m_options(options)
  , m_index(m_container.get<0>())
  , m_queue(m_container.get<1>())
{
  if (m_inner == nullptr) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("inner validator is nullptr"));
  }

  m_options.gracePeriod = std::max(m_options.gracePeriod, time::nanoseconds::zero());
}

void
ValidationPolicyCommandInterest::checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  m_inner->checkPolicy(data, state, continueValidation);
}

void
ValidationPolicyCommandInterest::checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
                                             const ValidationContinuation& continueValidation)
{
  this->cleanup();

  time::system_clock::TimePoint receiveTime = time::system_clock::now();
  parseCommandInterest(interest, state,
                       [=] (const Interest& interest, const shared_ptr<ValidationState>& state,
                            const Name& keyName, time::system_clock::TimePoint timestamp) {
                         m_inner->checkPolicy(interest, state,
                                              bind(&ValidationPolicyCommandInterest::checkTimestamp, this, _1, _2,
                                                   keyName, timestamp, receiveTime, continueValidation));
                       });
}

void
ValidationPolicyCommandInterest::cleanup()
{
  time::steady_clock::TimePoint expiring = time::steady_clock::now() - m_options.timestampTtl;

  while ((!m_queue.empty() && m_queue.front().lastRefreshed <= expiring) ||
         (m_options.maxTimestamps >= 0 &&
          m_queue.size() > static_cast<size_t>(m_options.maxTimestamps))) {
    m_queue.pop_front();
  }
}

void
ValidationPolicyCommandInterest::parseCommandInterest(const Interest& interest,
                                                      const shared_ptr<ValidationState>& state,
                                                      const CommandInterestValidationContinuation& continueValidation) const
{
  const Name& name = interest.getName();
  if (name.size() < command_interest::MIN_SIZE) {
    return state->fail({ValidationError::POLICY_ERROR, "Command interest name `" +
                        interest.getName().toUri() + "` is too short"});
  }

  const name::Component& timestampComp = name.at(command_interest::POS_TIMESTAMP);
  if (!timestampComp.isNumber()) {
    return state->fail({ValidationError::POLICY_ERROR, "Command interest `" +
                        interest.getName().toUri() + "` doesn't include timestamp component"});
  }

  SignatureInfo sig;
  try {
    sig.wireDecode(name[signed_interest::POS_SIG_INFO].blockFromValue());
  }
  catch (const tlv::Error&) {
    return state->fail({ValidationError::POLICY_ERROR, "Command interest `" +
                        interest.getName().toUri() + "` does not include SignatureInfo component"});
  }

  if (!sig.hasKeyLocator()) {
    return state->fail({ValidationError::INVALID_KEY_LOCATOR, "Command interest `" +
                        interest.getName().toUri() + "` does not include KeyLocator"});
  }

  const KeyLocator& keyLocator = sig.getKeyLocator();
  if (keyLocator.getType() != KeyLocator::KeyLocator_Name) {
    return state->fail({ValidationError::INVALID_KEY_LOCATOR, "Command interest `" +
                        interest.getName().toUri() + "` KeyLocator type is not key name"});
  }

  try {
    extractIdentityFromKeyName(keyLocator.getName());
  }
  catch (const std::invalid_argument&) {
    return state->fail({ValidationError::INVALID_KEY_LOCATOR, "Command interest `" +
                        interest.getName().toUri() + "` KeyLocator name `" + keyLocator.getName().toUri() +
                        "` violates naming conventions"});
  }

  continueValidation(interest, state,
                     keyLocator.getName(), time::fromUnixTimestamp(time::milliseconds(timestampComp.toNumber())));
}

void
ValidationPolicyCommandInterest::checkTimestamp(const shared_ptr<CertificateRequest>& certRequest,
                                                const shared_ptr<ValidationState>& state,
                                                const Name& keyName,
                                                time::system_clock::TimePoint timestamp,
                                                time::system_clock::TimePoint receiveTime,
                                                const ValidationContinuation& continueValidation)
{
  time::steady_clock::TimePoint now = time::steady_clock::now();

  // try to insert new record
  Queue::iterator i = m_queue.end();
  bool isNew = false;
  std::tie(i, isNew) = m_queue.push_back({keyName, timestamp, now});

  if (isNew) {
    // check grace period
    if (time::abs(timestamp - receiveTime) > m_options.gracePeriod) {
      // out of grace period, delete new record
      m_queue.erase(i);
      return state->fail({ValidationError::POLICY_ERROR, "Timestamp is out of grace for key " + keyName.toUri()});
    }
  }
  else {
    BOOST_ASSERT(i->keyName == keyName);

    // compare timestamp with last timestamp
    if (timestamp <= i->timestamp) {
      return state->fail({ValidationError::POLICY_ERROR, "Timestamp is reordered for key " + keyName.toUri()});
    }

    // set lastRefreshed field, and move to queue tail
    m_queue.erase(i);
    isNew = m_queue.push_back({keyName, timestamp, now}).second;
    BOOST_ASSERT(isNew);
  }

  continueValidation(certRequest, state);
}

} // namespace v2
} // namespace security
} // namespace ndn
