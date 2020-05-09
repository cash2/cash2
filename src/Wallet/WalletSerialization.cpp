// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <sstream>
#include <type_traits>

#include "Common/MemoryInputStream.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "Wallet/WalletErrors.h"
#include "WalletLegacy/KeysStorage.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletLegacy/WalletLegacySerializer.h"                                                
#include "WalletSerialization.h"

namespace {

//DO NOT CHANGE IT
struct WalletRecordDto {
  Crypto::PublicKey spendPublicKey;
  Crypto::SecretKey spendSecretKey;
  uint64_t pendingBalance = 0;
  uint64_t actualBalance = 0;
  uint64_t creationTimestamp = 0;
};

//DO NOT CHANGE IT
struct UnlockTransactionJobDto {
  uint32_t blockHeight;
  Crypto::Hash transactionHash;
  uint64_t walletIndex;
};

//DO NOT CHANGE IT
struct WalletTransactionDto {
  WalletTransactionDto() {}

  WalletTransactionDto(const CryptoNote::WalletTransaction& wallet) {
    state = wallet.state;
    timestamp = wallet.timestamp;
    blockHeight = wallet.blockHeight;
    hash = wallet.hash;
    totalAmount = wallet.totalAmount;
    fee = wallet.fee;
    creationTime = wallet.creationTime;
    unlockTime = wallet.unlockTime;
    extra = wallet.extra;
    if (wallet.secretKey)
    {
      secretKey = reinterpret_cast<const Crypto::SecretKey&>(wallet.secretKey.get());                     
    }                                                                                 
  }

  CryptoNote::WalletTransactionState state;
  uint64_t timestamp;
  uint32_t blockHeight;
  Crypto::Hash hash;
  int64_t totalAmount;
  uint64_t fee;
  uint64_t creationTime;
  uint64_t unlockTime;
  std::string extra;
  boost::optional<Crypto::SecretKey> secretKey = CryptoNote::NULL_SECRET_KEY;
};

//DO NOT CHANGE IT
struct WalletTransferDto {
  WalletTransferDto(uint32_t version) : version(version) {}
  WalletTransferDto(const CryptoNote::WalletTransfer& tr, uint32_t version) : WalletTransferDto(version) {
    address = tr.address;
    amount = tr.amount;
    type = static_cast<uint8_t>(tr.type);
  }

  std::string address;
  uint64_t amount;
  uint8_t type;
  uint32_t version;
};

void serialize(WalletRecordDto& value, CryptoNote::ISerializer& serializer) {
  serializer(value.spendPublicKey, "spend_public_key");
  serializer(value.spendSecretKey, "spend_secret_key");
  serializer(value.pendingBalance, "pending_balance");
  serializer(value.actualBalance, "actual_balance");
  serializer(value.creationTimestamp, "creation_timestamp");
}

void serialize(UnlockTransactionJobDto& value, CryptoNote::ISerializer& serializer) {
  serializer(value.blockHeight, "block_height");
  serializer(value.transactionHash, "transaction_hash");
  serializer(value.walletIndex, "wallet_index");
}

void serialize(WalletTransactionDto& value, CryptoNote::ISerializer& serializer) {
  typedef std::underlying_type<CryptoNote::WalletTransactionState>::type StateType;

  StateType state = static_cast<StateType>(value.state);
  serializer(state, "state");
  value.state = static_cast<CryptoNote::WalletTransactionState>(state);

  serializer(value.timestamp, "timestamp");
  CryptoNote::serializeBlockHeight(serializer, value.blockHeight, "block_height");
  serializer(value.hash, "hash");
  serializer(value.totalAmount, "total_amount");
  serializer(value.fee, "fee");
  serializer(value.creationTime, "creation_time");
  serializer(value.unlockTime, "unlock_time");
  serializer(value.extra, "extra");

  Crypto::SecretKey secretKey = reinterpret_cast<const Crypto::SecretKey&>(value.secretKey.get());
   
  serializer(secretKey, "secret_key");
  value.secretKey = secretKey;
}

void serialize(WalletTransferDto& value, CryptoNote::ISerializer& serializer) {
  serializer(value.address, "address");
  serializer(value.amount, "amount");
  serializer(value.type, "type");
}

template <typename Object>
std::string serialize(Object& obj, const std::string& name) {
  std::stringstream stream;
  Common::StdOutputStream output(stream);
  CryptoNote::BinaryOutputStreamSerializer s(output);

  s(obj, Common::StringView(name));

  stream.flush();
  return stream.str();
}

std::string encrypt(const std::string& plain, CryptoNote::CryptoContext& cryptoContext) {
  std::string cipher;
  cipher.resize(plain.size());

  Crypto::chacha8(plain.data(), plain.size(), cryptoContext.key, cryptoContext.iv, &cipher[0]);

  return cipher;
}

void addToStream(const std::string& cipher, const std::string& name, Common::IOutputStream& destination) {
  CryptoNote::BinaryOutputStreamSerializer s(destination);
  s(const_cast<std::string& >(cipher), name);
}

template<typename Object>
void serializeEncrypted(Object& obj, const std::string& name, CryptoNote::CryptoContext& cryptoContext, Common::IOutputStream& destination) {
  std::string plain = serialize(obj, name);
  std::string cipher = encrypt(plain, cryptoContext);

  addToStream(cipher, name, destination);
}

std::string readCipher(Common::IInputStream& source, const std::string& name) {
  std::string cipher;
  CryptoNote::BinaryInputStreamSerializer s(source);
  s(cipher, name);

  return cipher;
}

std::string decrypt(const std::string& cipher, CryptoNote::CryptoContext& cryptoContext) {
  std::string plain;
  plain.resize(cipher.size());

  Crypto::chacha8(cipher.data(), cipher.size(), cryptoContext.key, cryptoContext.iv, &plain[0]);
  return plain;
}

template<typename Object>
void deserialize(Object& obj, const std::string& name, const std::string& plain) {
  Common::MemoryInputStream stream(plain.data(), plain.size());
  CryptoNote::BinaryInputStreamSerializer s(stream);
  s(obj, Common::StringView(name));
}

template<typename Object>
void deserializeEncrypted(Object& obj, const std::string& name, CryptoNote::CryptoContext& cryptoContext, Common::IInputStream& source) {
  std::string cipher = readCipher(source, name);
  std::string plain = decrypt(cipher, cryptoContext);

  deserialize(obj, name, plain);
}

} // end anonymous namespace

namespace CryptoNote {

const uint32_t WalletSerializer::WALLET_SERIALIZATION_VERSION = 5;


// Public functions


WalletSerializer::WalletSerializer(
  ITransfersObserver& transfersObserver,
  Crypto::PublicKey& viewPublicKey,
  Crypto::SecretKey& viewSecretKey,
  uint64_t& actualBalance,
  uint64_t& pendingBalance,
  WalletsContainer& walletsContainer,
  TransfersSyncronizer& synchronizer,
  UnlockTransactionJobs& unlockTransactions,
  WalletTransactions& transactions,
  WalletTransfers& transfers,
  uint32_t transactionSoftLockTime,
  UncommitedTransactions& uncommitedTransactions
) :
  m_transfersObserver(transfersObserver),
  m_viewPublicKey(viewPublicKey),
  m_viewPrivateKey(viewSecretKey),
  m_actualBalance(actualBalance),
  m_pendingBalance(pendingBalance),
  m_walletsContainer(walletsContainer),
  m_transfersSynchronizer(synchronizer),
  m_unlockTransactions(unlockTransactions),
  m_walletTransactions(transactions),
  m_walletTransfers(transfers),
  m_transactionSoftLockTime(transactionSoftLockTime),
  m_uncommitedTransactions(uncommitedTransactions)
{ }

void WalletSerializer::load(const std::string& password, Common::IInputStream& source)
{
  CryptoNote::BinaryInputStreamSerializer s(source);

  s.beginObject("wallet");

  uint32_t version = loadVersion(source);

  CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = version;
                                                          
  if (version == 5)
  {
    loadWallet(source, password, version);
  }
  else
  {
    throw std::system_error(make_error_code(error::WRONG_VERSION));
  }

  s.endObject();
}

void WalletSerializer::save(const std::string& password, Common::IOutputStream& destination, bool saveDetails, bool saveCache)
{
  CryptoContext cryptoContext = generateCryptoContext(password);

  CryptoNote::BinaryOutputStreamSerializer s(destination);
  s.beginObject("wallet");

  saveVersion(destination);
  saveIv(destination, cryptoContext.iv);

  saveViewKeys(destination, cryptoContext);
  saveWallets(destination, saveCache, cryptoContext);
  saveFlags(saveDetails, saveCache, destination, cryptoContext);

  if (saveDetails)
  {
    saveTransactions(destination, cryptoContext);
    saveTransfers(destination, cryptoContext);
  }

  if (saveCache)
  {
    saveBalances(destination, saveCache, cryptoContext);
    saveTransfersSynchronizer(destination, cryptoContext);
    saveUnlockTransactionsJobs(destination, cryptoContext);
    saveUncommitedTransactions(destination, cryptoContext);
  }

  s.endObject();
}


// Private functions

void WalletSerializer::checkKeys()
{
  Crypto::PublicKey viewPublicKey;

  if (!Crypto::secret_key_to_public_key(m_viewPrivateKey, viewPublicKey) || m_viewPublicKey != viewPublicKey)
  {
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD)); // Probably need to change this error message to say wrong view keys instead of wrong password
  }
}

CryptoContext WalletSerializer::generateCryptoContext(const std::string& password)
{
  CryptoContext cryptoContext;

  Crypto::cn_context cnContext;

  Crypto::generate_chacha8_key(cnContext, password, cryptoContext.key);

  cryptoContext.iv = Crypto::rand<Crypto::chacha8_iv>();

  return cryptoContext;
}

void WalletSerializer::generateKey(const std::string& password, Crypto::chacha8_key& key)
{
  Crypto::cn_context context;
  Crypto::generate_chacha8_key(context, password, key);
}

void WalletSerializer::initTransactionPool() {
  std::unordered_set<Crypto::Hash> uncommitedTransactionsSet;
  std::transform(m_uncommitedTransactions.begin(), m_uncommitedTransactions.end(), std::inserter(uncommitedTransactionsSet, uncommitedTransactionsSet.end()),
    [](const UncommitedTransactions::value_type& pair) {
      return getObjectHash(pair.second);
    });
  m_transfersSynchronizer.initTransactionPool(uncommitedTransactionsSet);
}

void WalletSerializer::loadBalances(Common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(m_actualBalance, "actual_balance", cryptoContext, source);
  cryptoContext.incIv();

  deserializeEncrypted(m_pendingBalance, "pending_balance", cryptoContext, source);
  cryptoContext.incIv();
}

void WalletSerializer::loadFlags(bool& details, bool& cache, Common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(details, "details", cryptoContext, source);
  cryptoContext.incIv();

  deserializeEncrypted(cache, "cache", cryptoContext, source);
  cryptoContext.incIv();
}

void WalletSerializer::loadIv(Common::IInputStream& source, Crypto::chacha8_iv& iv) {
  CryptoNote::BinaryInputStreamSerializer s(source);

  s.binary(static_cast<void *>(&iv.data), sizeof(iv.data), "chacha_iv");
}

void WalletSerializer::loadKeys(Common::IInputStream& source, CryptoContext& cryptoContext) {
  loadViewPublicKey(source, cryptoContext);
  loadViewPrivateKey(source, cryptoContext);
}

void WalletSerializer::loadViewPublicKey(Common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(m_viewPublicKey, "public_key", cryptoContext, source);
  cryptoContext.incIv();
}

void WalletSerializer::loadViewPrivateKey(Common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(m_viewPrivateKey, "secret_key", cryptoContext, source);
  cryptoContext.incIv();
}

void WalletSerializer::loadTransactions(Common::IInputStream& source, CryptoContext& cryptoContext) {
  uint64_t transactionsCount = 0;
  deserializeEncrypted(transactionsCount, "transactions_count", cryptoContext, source);
  cryptoContext.incIv();

  m_walletTransactions.get<RandomAccessIndex>().reserve(transactionsCount);

  for (uint64_t i = 0; i < transactionsCount; ++i) {
    WalletTransactionDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransaction tx;
    tx.state = dto.state;
    tx.timestamp = dto.timestamp;
    tx.blockHeight = dto.blockHeight;
    tx.hash = dto.hash;
    tx.totalAmount = dto.totalAmount;
    tx.fee = dto.fee;
    tx.creationTime = dto.creationTime;
    tx.unlockTime = dto.unlockTime;
    tx.extra = dto.extra;
    tx.isBase = false;
    if (dto.secretKey)
    {
      tx.secretKey = reinterpret_cast<const Crypto::SecretKey&>(dto.secretKey.get());
    }

    m_walletTransactions.get<RandomAccessIndex>().push_back(std::move(tx));
  }
}

void WalletSerializer::loadTransfers(Common::IInputStream& source, CryptoContext& cryptoContext, uint32_t version) {
  uint64_t transfersCount = 0;
  deserializeEncrypted(transfersCount, "transfers_count", cryptoContext, source);
  cryptoContext.incIv();

  m_walletTransfers.reserve(transfersCount);

  for (uint64_t i = 0; i < transfersCount; ++i) {
    uint64_t transactionIndex = 0;
    deserializeEncrypted(transactionIndex, "transaction_id", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransferDto dto(version);
    deserializeEncrypted(dto, "transfer", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransfer walletTransfer;
    walletTransfer.address = dto.address;
    walletTransfer.amount = dto.amount;
    walletTransfer.type = static_cast<WalletTransferType>(dto.type);

    m_walletTransfers.push_back(std::make_pair(transactionIndex, walletTransfer));
  }
}

void WalletSerializer::loadTransfersSynchronizer(Common::IInputStream& source, CryptoContext& cryptoContext) {
  std::string deciphered;
  deserializeEncrypted(deciphered, "transfers_synchronizer", cryptoContext, source);
  cryptoContext.incIv();

  std::stringstream stream(deciphered);
  deciphered.clear();

  m_transfersSynchronizer.load(stream);
}

void WalletSerializer::loadUncommitedTransactions(Common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(m_uncommitedTransactions, "uncommited_transactions", cryptoContext, source);
}

void WalletSerializer::loadUnlockTransactionsJobs(Common::IInputStream& source, CryptoContext& cryptoContext) {
  auto& unlockTransactions = m_unlockTransactions.get<TransactionHashIndex>();
  auto& walletsContainer = m_walletsContainer.get<RandomAccessIndex>();
  const uint64_t walletsSize = walletsContainer.size();

  uint64_t jobsCount = 0;
  deserializeEncrypted(jobsCount, "unlock_transactions_jobs_count", cryptoContext, source);
  cryptoContext.incIv();

  for (uint64_t i = 0; i < jobsCount; ++i) {
    UnlockTransactionJobDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();

    assert(dto.walletIndex < walletsSize);

    UnlockTransactionJob job;
    job.blockHeight = dto.blockHeight;
    job.transactionHash = dto.transactionHash;
    job.container = walletsContainer[dto.walletIndex].container;

    unlockTransactions.insert(std::move(job));
  }
}

uint32_t WalletSerializer::loadVersion(Common::IInputStream& source) {
  CryptoNote::BinaryInputStreamSerializer s(source);

  uint32_t version = std::numeric_limits<uint32_t>::max();
  s(version, "version");

  return version;
}

void WalletSerializer::loadWallet(Common::IInputStream& source, const std::string& password, uint32_t version) {
  CryptoNote::CryptoContext cryptoContext;

  bool details = false;
  bool cache = false;

  loadIv(source, cryptoContext.iv);
  generateKey(password, cryptoContext.key);

  loadKeys(source, cryptoContext);
  checkKeys();

  loadWallets(source, cryptoContext);
  subscribeWallets();

  loadFlags(details, cache, source, cryptoContext);

  if (details) {
    loadTransactions(source, cryptoContext);
    loadTransfers(source, cryptoContext, version);
  }

  if (cache) {
    loadBalances(source, cryptoContext);
    loadTransfersSynchronizer(source, cryptoContext);
    loadUnlockTransactionsJobs(source, cryptoContext);
    loadUncommitedTransactions(source, cryptoContext);
    initTransactionPool();
  } else {
    resetCachedBalance();
  }

  if (details && cache) {
    updateTransactionsBaseStatus();
  }
}

void WalletSerializer::loadWallets(Common::IInputStream& source, CryptoContext& cryptoContext) {
  auto& index = m_walletsContainer.get<RandomAccessIndex>();

  uint64_t walletsCount = 0;
  deserializeEncrypted(walletsCount, "wallets_count", cryptoContext, source);
  cryptoContext.incIv();

  bool isTrackingMode;

  for (uint64_t i = 0; i < walletsCount; ++i) {
    WalletRecordDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();

    if (i == 0) {
      isTrackingMode = dto.spendSecretKey == NULL_SECRET_KEY;
    } else if ((isTrackingMode && dto.spendSecretKey != NULL_SECRET_KEY) || (!isTrackingMode && dto.spendSecretKey == NULL_SECRET_KEY)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS), "All addresses must be whether tracking or not");
    }

    if (dto.spendSecretKey != NULL_SECRET_KEY) {
      Crypto::PublicKey restoredSpendPublicKey;
      bool r = Crypto::secret_key_to_public_key(dto.spendSecretKey, restoredSpendPublicKey);

      if (!r || dto.spendPublicKey != restoredSpendPublicKey) {
        throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Restored spend public key doesn't correspond to secret key");
      }
    } else {
      if (!Crypto::check_key(dto.spendPublicKey)) {
        throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Public spend key is incorrect");
      }
    }

    WalletRecord walletRecord;
    walletRecord.spendPublicKey = dto.spendPublicKey;
    walletRecord.spendSecretKey = dto.spendSecretKey;
    walletRecord.actualBalance = dto.actualBalance;
    walletRecord.pendingBalance = dto.pendingBalance;
    walletRecord.creationTimestamp = static_cast<time_t>(dto.creationTimestamp);
    walletRecord.container = reinterpret_cast<CryptoNote::ITransfersContainer*>(i); //dirty hack. container field must be unique

    index.push_back(walletRecord);
  }
}

void WalletSerializer::resetCachedBalance() {
  for (auto it = m_walletsContainer.begin(); it != m_walletsContainer.end(); ++it) {
    m_walletsContainer.modify(it, [](WalletRecord& walletRecord) {
      walletRecord.actualBalance = 0;
      walletRecord.pendingBalance = 0;
    });
  }
}

void WalletSerializer::saveBalances(Common::IOutputStream& destination, bool saveCache, CryptoContext& cryptoContext) {
  // uint64_t actualBalance = saveCache ? m_actualBalance : 0;
  // uint64_t pendingBalance = saveCache ? m_pendingBalance : 0;

  uint64_t actualBalance = 0;
  uint64_t pendingBalance = 0;

  if (saveCache)
  {
    actualBalance = m_actualBalance;
    pendingBalance = m_pendingBalance;
  }

  serializeEncrypted(actualBalance, "actual_balance", cryptoContext, destination);
  cryptoContext.incIv();

  serializeEncrypted(pendingBalance, "pending_balance", cryptoContext, destination);
  cryptoContext.incIv();
}

void WalletSerializer::saveFlags(bool saveDetails, bool saveCache, Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  serializeEncrypted(saveDetails, "details", cryptoContext, destination);
  cryptoContext.incIv();

  serializeEncrypted(saveCache, "cache", cryptoContext, destination);
  cryptoContext.incIv();
}

void WalletSerializer::saveIv(Common::IOutputStream& destination, Crypto::chacha8_iv& iv) {
  BinaryOutputStreamSerializer s(destination);
  s.binary(reinterpret_cast<void *>(&iv.data), sizeof(iv.data), "chacha_iv");
}

void WalletSerializer::saveViewKeys(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  saveViewPublicKey(destination, cryptoContext);
  saveViewPrivateKey(destination, cryptoContext);
}

void WalletSerializer::saveViewPublicKey(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  serializeEncrypted(m_viewPublicKey, "public_key", cryptoContext, destination);
  cryptoContext.incIv();
}

void WalletSerializer::saveViewPrivateKey(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  serializeEncrypted(m_viewPrivateKey, "secret_key", cryptoContext, destination);
  cryptoContext.incIv();
}

void WalletSerializer::saveTransactions(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  uint64_t walletTransactionsCount = m_walletTransactions.size();
  serializeEncrypted(walletTransactionsCount, "transactions_count", cryptoContext, destination);
  cryptoContext.incIv();

  for (const WalletTransaction& walletTransaction: m_walletTransactions) {
    WalletTransactionDto dto(walletTransaction);
    serializeEncrypted(dto, "", cryptoContext, destination);
    cryptoContext.incIv();
  }
}

void WalletSerializer::saveTransfers(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  uint64_t walletTransfersCount = m_walletTransfers.size();
  serializeEncrypted(walletTransfersCount, "transfers_count", cryptoContext, destination);
  cryptoContext.incIv();

  for (const TransactionTransferPair& kv : m_walletTransfers) {
    uint64_t transactionIndex = kv.first;
    WalletTransfer walletTransfer = kv.second;

    WalletTransferDto dto(walletTransfer, WALLET_SERIALIZATION_VERSION);

    serializeEncrypted(transactionIndex, "transaction_id", cryptoContext, destination);
    cryptoContext.incIv();

    serializeEncrypted(dto, "transfer", cryptoContext, destination);
    cryptoContext.incIv();
  }
}

void WalletSerializer::saveTransfersSynchronizer(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  std::stringstream stream;
  m_transfersSynchronizer.save(stream);
  stream.flush();

  std::string plain = stream.str();
  serializeEncrypted(plain, "transfers_synchronizer", cryptoContext, destination);
  cryptoContext.incIv();
}

void WalletSerializer::saveUncommitedTransactions(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  serializeEncrypted(m_uncommitedTransactions, "uncommited_transactions", cryptoContext, destination);
}

void WalletSerializer::saveUnlockTransactionsJobs(Common::IOutputStream& destination, CryptoContext& cryptoContext) {
  auto& unlockTransactions = m_unlockTransactions.get<TransactionHashIndex>();
  auto& walletsContainer = m_walletsContainer.get<TransfersContainerIndex>();

  uint64_t jobsCount = unlockTransactions.size();
  serializeEncrypted(jobsCount, "unlock_transactions_jobs_count", cryptoContext, destination);
  cryptoContext.incIv();

  for (const auto& unlockTransaction: unlockTransactions) {
    auto containerIt = walletsContainer.find(unlockTransaction.container);
    assert(containerIt != walletsContainer.end());

    auto rndIt = m_walletsContainer.project<RandomAccessIndex>(containerIt);
    assert(rndIt != m_walletsContainer.get<RandomAccessIndex>().end());

    uint64_t walletIndex = std::distance(m_walletsContainer.get<RandomAccessIndex>().begin(), rndIt);

    UnlockTransactionJobDto dto;
    dto.blockHeight = unlockTransaction.blockHeight;
    dto.transactionHash = unlockTransaction.transactionHash;
    dto.walletIndex = walletIndex;

    serializeEncrypted(dto, "", cryptoContext, destination);
    cryptoContext.incIv();
  }
}

void WalletSerializer::saveVersion(Common::IOutputStream& destination) {
  uint32_t version = WALLET_SERIALIZATION_VERSION;

  BinaryOutputStreamSerializer s(destination);
  s(version, "version");
}

void WalletSerializer::saveWallets(Common::IOutputStream& destination, bool saveCache, CryptoContext& cryptoContext) {
  auto& walletsContainer = m_walletsContainer.get<RandomAccessIndex>();

  uint64_t walletContainerCount = walletsContainer.size();
  serializeEncrypted(walletContainerCount, "wallets_count", cryptoContext, destination);
  cryptoContext.incIv();

  for (const WalletRecord& walletRecord: walletsContainer) {
    WalletRecordDto dto;
    dto.spendPublicKey = walletRecord.spendPublicKey;
    dto.spendSecretKey = walletRecord.spendSecretKey;
    dto.pendingBalance = saveCache ? walletRecord.pendingBalance : 0;
    dto.actualBalance = saveCache ? walletRecord.actualBalance : 0;
    dto.creationTimestamp = static_cast<uint64_t>(walletRecord.creationTimestamp);

    serializeEncrypted(dto, "", cryptoContext, destination);
    cryptoContext.incIv();
  }
}

void WalletSerializer::subscribeWallets() {
  auto& walletsContainer = m_walletsContainer.get<RandomAccessIndex>();

  for (auto it = walletsContainer.begin(); it != walletsContainer.end(); ++it) {
    const WalletRecord& walletRecord = *it;

    AccountSubscription sub;
    sub.keys.address.viewPublicKey = m_viewPublicKey;
    sub.keys.address.spendPublicKey = walletRecord.spendPublicKey;
    sub.keys.viewSecretKey = m_viewPrivateKey;
    sub.keys.spendSecretKey = walletRecord.spendSecretKey;
    sub.transactionSpendableAge = m_transactionSoftLockTime;
    sub.syncStart.height = 0;
    sub.syncStart.timestamp = std::max(static_cast<uint64_t>(walletRecord.creationTimestamp), ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;

    auto& subscription = m_transfersSynchronizer.addSubscription(sub);
    bool r = walletsContainer.modify(it, [&subscription] (WalletRecord& rec) { rec.container = &subscription.getContainer(); });
    assert(r);

    subscription.addObserver(&m_transfersObserver);
  }
}

// can't do it in loadTransactions, TransfersContainer is not yet loaded
void WalletSerializer::updateTransactionsBaseStatus() {
  auto& walletTransactions = m_walletTransactions.get<RandomAccessIndex>();
  auto begin = std::begin(walletTransactions);
  auto end = std::end(walletTransactions);
  for (; begin != end; ++begin) {
    walletTransactions.modify(begin, [this](WalletTransaction& tx) {
      const auto& wallets = m_walletsContainer.get<RandomAccessIndex>();
      TransactionInformation txInfo;
      auto it = std::find_if(std::begin(wallets), std::end(wallets), [&](const WalletRecord& rec) {
        assert(rec.container != nullptr);
        return rec.container->getTransactionInformation(tx.hash, txInfo);
      });

      tx.isBase = it != std::end(wallets) && txInfo.totalAmountIn == 0;
    });
  }
}

void WalletSerializer::updateTransfersSign() {
  auto it = m_walletTransfers.begin();
  while (it != m_walletTransfers.end()) {
    WalletTransfer walletTransfer = it->second;
    if (walletTransfer.amount < 0) {
      walletTransfer.amount = -walletTransfer.amount;
      ++it;
    } else {
      it = m_walletTransfers.erase(it);
    }
  }
}

} // end namespace CryptoNote
