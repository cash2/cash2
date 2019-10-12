// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>

#include "Common/MemoryInputStream.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Wallet/WalletErrors.h"
#include "WalletLegacy/KeysStorage.h"
#include "WalletLegacy/WalletLegacyCache.h"
#include "WalletLegacySerializer.h"

namespace CryptoNote {

uint32_t WALLET_LEGACY_SERIALIZATION_VERSION = 2;                                                 


// Public functions


WalletLegacySerializer::WalletLegacySerializer(CryptoNote::AccountBase& account, WalletLegacyCache& walletLegacyCache) :
  m_accountRef(account),
  m_walletLegacyCacheRef(walletLegacyCache),
  m_walletSerializationVersion(2)
{
}

void WalletLegacySerializer::deserialize(std::istream& inputStream, const std::string& password, std::string& transfersSynchronizerCache) {
  Common::StdInputStream encryptedInputStream(inputStream);
  CryptoNote::BinaryInputStreamSerializer encryptedDataDeserializer(encryptedInputStream);

  encryptedDataDeserializer.beginObject("wallet");

  // deserialize version
  uint32_t version;
  encryptedDataDeserializer(version, "version");

  CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = version;

  // deserialize iv
  Crypto::chacha8_iv iv;
  encryptedDataDeserializer(iv, "iv");

  // deserialize encrypted data
  std::string encryptedStr;
  encryptedDataDeserializer(encryptedStr, "data");

  encryptedDataDeserializer.endObject();

  // decrypt data
  std::string decryptedStr;
  decrypt(encryptedStr, decryptedStr, iv, password);

  // copy plain data
  Common::MemoryInputStream decryptedDataMemoryInputStream(decryptedStr.data(), decryptedStr.size()); 
  CryptoNote::BinaryInputStreamSerializer decryptedDataDeserializer(decryptedDataMemoryInputStream);

  CryptoNote::KeysStorage keys;

  try
  {
    // deserialize keys
    keys.deserialize(decryptedDataDeserializer, "keys");
  }
  catch (const std::runtime_error&)
  {
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
  }

  CryptoNote::AccountKeys account;
  account.address.spendPublicKey = keys.spendPublicKey;
  account.spendSecretKey = keys.spendSecretKey;
  account.address.viewPublicKey = keys.viewPublicKey;
  account.viewSecretKey = keys.viewSecretKey;

  m_accountRef.setAccountKeys(account);
  m_accountRef.set_createtime(keys.creationTimestamp);

  throwIfKeysMissmatch(m_accountRef.getAccountKeys().viewSecretKey, m_accountRef.getAccountKeys().address.viewPublicKey);

  if (m_accountRef.getAccountKeys().spendSecretKey != NULL_SECRET_KEY) {
    throwIfKeysMissmatch(m_accountRef.getAccountKeys().spendSecretKey, m_accountRef.getAccountKeys().address.spendPublicKey);
  } else {
    if (!Crypto::check_key(m_accountRef.getAccountKeys().address.spendPublicKey)) {
      throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
    }
  }

  // deserialize deatailsSaved
  bool detailsSaved;
  decryptedDataDeserializer(detailsSaved, "has_details");

  if (detailsSaved) {
    // deserialize m_walletLegacyCacheRef
    decryptedDataDeserializer(m_walletLegacyCacheRef, "details");
  }

  // deserialize transfersSynchronizerCache
  decryptedDataDeserializer.binary(transfersSynchronizerCache, "cache");
}

void WalletLegacySerializer::serialize(std::ostream& outputStream, const std::string& password, bool saveDetailed, const std::string& transfersSynchronizerCache) {

  CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = m_walletSerializationVersion;                                            

  std::stringstream decryptedStringStream;
  Common::StdOutputStream decryptedOutputStream(decryptedStringStream);
  CryptoNote::BinaryOutputStreamSerializer decryptedDataSerializer(decryptedOutputStream);

  CryptoNote::KeysStorage keys;
  CryptoNote::AccountKeys account = m_accountRef.getAccountKeys();
  keys.creationTimestamp = m_accountRef.get_createtime();
  keys.spendPublicKey = account.address.spendPublicKey;
  keys.spendSecretKey = account.spendSecretKey;
  keys.viewPublicKey = account.address.viewPublicKey;
  keys.viewSecretKey = account.viewSecretKey;

  // serialize keys
  keys.serialize(decryptedDataSerializer, "keys");

  // serialize saveDetailed
  decryptedDataSerializer(saveDetailed, "has_details");

  if (saveDetailed) {
    // serialize m_walletLegacyCacheRef
    decryptedDataSerializer(m_walletLegacyCacheRef, "details");
  }

  // serialize transfersSynchronizerCache
  decryptedDataSerializer.binary(const_cast<std::string&>(transfersSynchronizerCache), "cache");

  std::string decryptedStr = decryptedStringStream.str();

  // encrypt the plain data
  std::string encryptedStr;
  Crypto::chacha8_iv iv = encrypt(decryptedStr, password, encryptedStr);

  uint32_t version = m_walletSerializationVersion;
  Common::StdOutputStream encryptedOutputStream(outputStream);
  CryptoNote::BinaryOutputStreamSerializer encryptedDataSerializer(encryptedOutputStream);
  encryptedDataSerializer.beginObject("wallet");
  // serialize version
  encryptedDataSerializer(version, "version");
  // serialize iv
  encryptedDataSerializer(iv, "iv");
  // serialize encrypted data
  encryptedDataSerializer(encryptedStr, "data");
  encryptedDataSerializer.endObject();

  outputStream.flush();
}


// Private functions


void WalletLegacySerializer::decrypt(const std::string& encryptedStr, std::string& decryptedStr, Crypto::chacha8_iv iv, const std::string& password) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  Crypto::generate_chacha8_key(context, password, key);

  decryptedStr.resize(encryptedStr.size());

  Crypto::chacha8(encryptedStr.data(), encryptedStr.size(), key, iv, &decryptedStr[0]);
}

Crypto::chacha8_iv WalletLegacySerializer::encrypt(const std::string& decryptedStr, const std::string& password, std::string& encryptedStr) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  Crypto::generate_chacha8_key(context, password, key);

  encryptedStr.resize(decryptedStr.size());

  Crypto::chacha8_iv iv = Crypto::rand<Crypto::chacha8_iv>();
  Crypto::chacha8(decryptedStr.data(), decryptedStr.size(), key, iv, &encryptedStr[0]);

  return iv;
}

void WalletLegacySerializer::throwIfKeysMissmatch(const Crypto::SecretKey& privateKey, const Crypto::PublicKey& expectedPublicKey) {
  if (!verifyKeys(privateKey, expectedPublicKey))
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
}

bool WalletLegacySerializer::verifyKeys(const Crypto::SecretKey& privateKey, const Crypto::PublicKey& expectedPublicKey) {
  Crypto::PublicKey publicKey;
  bool r = Crypto::secret_key_to_public_key(privateKey, publicKey);
  return r && expectedPublicKey == publicKey;
}

} // end namespace CryptoNote
