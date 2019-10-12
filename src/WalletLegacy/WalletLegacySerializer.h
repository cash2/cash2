// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <vector>
#include <ostream>
#include <istream>

#include "crypto/hash.h"
#include "crypto/chacha8.h"
#include "WalletLegacyCache.h"

namespace CryptoNote {
class AccountBase;
class ISerializer;
}

namespace CryptoNote {

class WalletLegacySerializer {
public:
  WalletLegacySerializer(CryptoNote::AccountBase& account, WalletLegacyCache& walletLegacyCache);
  void deserialize(std::istream& inputStream, const std::string& password, std::string& transfersSynchronizerCache);
  void serialize(std::ostream& outputStream, const std::string& password, bool saveDetailed, const std::string& transfersSynchronizerCache);

private:
  void decrypt(const std::string& encryptedStr, std::string& decryptedStr, Crypto::chacha8_iv iv, const std::string& password);
  Crypto::chacha8_iv encrypt(const std::string& decryptedStr, const std::string& password, std::string& encryptedStr);
  void throwIfKeysMissmatch(const Crypto::SecretKey& privateKey, const Crypto::PublicKey& expectedPublicKey);
  bool verifyKeys(const Crypto::SecretKey& privateKey, const Crypto::PublicKey& expectedPublicKey);

  CryptoNote::AccountBase& m_accountRef;
  WalletLegacyCache& m_walletLegacyCacheRef;
  const uint32_t m_walletSerializationVersion;
};

extern uint32_t WALLET_LEGACY_SERIALIZATION_VERSION;
                                                   
} //namespace CryptoNote
