// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "SynchronizationState.h"

using namespace Common;

namespace CryptoNote {


// Public functions


void SynchronizationState::addBlocks(const Crypto::Hash* blockHashes, uint32_t height, uint32_t count) {
  assert(blockHashes);
  size_t size = m_blockchain.size();
  assert(size == height);
  m_blockchain.insert(m_blockchain.end(), blockHashes, blockHashes + count);
}

SynchronizationState::CheckResult SynchronizationState::checkInterval(const BlockchainInterval& interval) const {
  assert(interval.startHeight <= m_blockchain.size());

  CheckResult result;

  uint32_t intervalEndHeight = interval.startHeight + static_cast<uint32_t>(interval.blocks.size());
  uint32_t endHeight = std::min(static_cast<uint32_t>(m_blockchain.size()), intervalEndHeight);

  for (uint32_t i = interval.startHeight; i < endHeight; ++i) {
    if (m_blockchain[i] != interval.blocks[i - interval.startHeight]) {
      result.detachRequired = true;
      result.detachHeight = i;
      break;
    }
  }

  if (result.detachRequired) {
    result.hasNewBlocks = true;
    result.newBlockHeight = result.detachHeight;
    return result;
  }

  if (intervalEndHeight > m_blockchain.size()) {
    result.hasNewBlocks = true;
    result.newBlockHeight = static_cast<uint32_t>(m_blockchain.size());
  }

  return result;
}

void SynchronizationState::detach(uint32_t height) {
  assert(height < m_blockchain.size());
  m_blockchain.resize(height);
}

uint32_t SynchronizationState::getHeight() const {
  return static_cast<uint32_t>(m_blockchain.size());
}

const std::vector<Crypto::Hash>& SynchronizationState::getKnownBlockHashes() const {
  return m_blockchain;
}

std::vector<Crypto::Hash> SynchronizationState::getShortHistory(uint32_t localHeight) const {
  std::vector<Crypto::Hash> history;
  uint32_t i = 0;
  uint32_t current_multiplier = 1;
  uint32_t size = std::min(static_cast<uint32_t>(m_blockchain.size()), localHeight + 1);

  if (!size)
  {
    return history;
  }

  uint32_t current_back_offset = 1;
  bool genesis_included = false;

  while (current_back_offset < size) {
    history.push_back(m_blockchain[size - current_back_offset]);
    if (size - current_back_offset == 0)
    {
      genesis_included = true;
    }

    if (i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_back_offset += current_multiplier *= 2;
    }

    ++i;
  }

  if (!genesis_included)
  {
    history.push_back(m_blockchain[0]);
  }

  return history;
}

void SynchronizationState::load(std::istream& in) { // load from disk into memory
  StdInputStream stream(in);
  CryptoNote::BinaryInputStreamSerializer s(stream);
  serialize(s, "state");
}

void SynchronizationState::save(std::ostream& os) { // save to disk
  StdOutputStream stream(os);
  CryptoNote::BinaryOutputStreamSerializer s(stream);
  serialize(s, "state");
}

CryptoNote::ISerializer& SynchronizationState::serialize(CryptoNote::ISerializer& s, const std::string& name) {
  s.beginObject(name);
  s(m_blockchain, "blockchain");
  s.endObject();
  return s;
}

}
