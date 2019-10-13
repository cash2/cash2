// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <vector>
#include <map>

#include "CommonTypes.h"
#include "IStreamSerializable.h"
#include "Serialization/ISerializer.h"

namespace CryptoNote {

class SynchronizationState : public IStreamSerializable {
public:

  struct CheckResult {
    bool detachRequired = false;
    uint32_t detachHeight = 0;
    bool hasNewBlocks = false;
    uint32_t newBlockHeight = 0;
  };

  explicit SynchronizationState(const Crypto::Hash& genesisBlockHash) {
    m_blockchain.push_back(genesisBlockHash);
  }

  void addBlocks(const Crypto::Hash* blockHashes, uint32_t height, uint32_t count);
  CheckResult checkInterval(const BlockchainInterval& interval) const;
  void detach(uint32_t height);
  uint32_t getHeight() const;
  const std::vector<Crypto::Hash>& getKnownBlockHashes() const;
  std::vector<Crypto::Hash> getShortHistory(uint32_t localHeight) const;
  virtual void load(std::istream& in) override;
  virtual void save(std::ostream& os) override;
  CryptoNote::ISerializer& serialize(CryptoNote::ISerializer& s, const std::string& name);

private:

  std::vector<Crypto::Hash> m_blockchain;
};

} // end namespace CryptoNote
