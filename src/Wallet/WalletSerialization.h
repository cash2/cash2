// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/IInputStream.h"
#include "Common/IOutputStream.h"
#include "crypto/chacha8.h"
#include "IWallet.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Transfers/TransfersSynchronizer.h"
#include "WalletIndexes.h"

namespace CryptoNote
{

struct CryptoContext
{
  Crypto::chacha8_key key;
  Crypto::chacha8_iv iv;

  void incIv()
  {
    uint64_t* i = reinterpret_cast<uint64_t*>(&iv.data[0]);
    (*i)++;
  }
};

class WalletSerializer
{

public:

  WalletSerializer(
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
  );
  
  void load(const std::string& password, Common::IInputStream& source);
  void save(const std::string& password, Common::IOutputStream& destination, bool saveDetails, bool saveCache);

private:

  static const uint32_t WALLET_SERIALIZATION_VERSION;
  
  void checkKeys();
  CryptoContext generateCryptoContext(const std::string& password);
  void generateKey(const std::string& password, Crypto::chacha8_key& key);
  void initTransactionPool();
  void loadBalances(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadFlags(bool& details, bool& cache, Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadIv(Common::IInputStream& source, Crypto::chacha8_iv& iv);
  void loadKeys(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadObsoleteChange(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadObsoleteSpentOutputs(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadViewPublicKey(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadViewPrivateKey(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadTransactions(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadTransfers(Common::IInputStream& source, CryptoContext& cryptoContext, uint32_t version);
  void loadTransfersSynchronizer(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadUncommitedTransactions(Common::IInputStream& source, CryptoContext& cryptoContext);
  void loadUnlockTransactionsJobs(Common::IInputStream& source, CryptoContext& cryptoContext);
  uint32_t loadVersion(Common::IInputStream& source);
  void loadWallet(Common::IInputStream& source, const std::string& password, uint32_t version);
  void loadWallets(Common::IInputStream& source, CryptoContext& cryptoContext);
  void resetCachedBalance();
  void saveBalances(Common::IOutputStream& destination, bool saveCache, CryptoContext& cryptoContext);
  void saveFlags(bool saveDetails, bool saveCache, Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveIv(Common::IOutputStream& destination, Crypto::chacha8_iv& iv);
  void saveViewKeys(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveViewPublicKey(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveViewPrivateKey(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveTransactions(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveTransfers(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveTransfersSynchronizer(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveUncommitedTransactions(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveUnlockTransactionsJobs(Common::IOutputStream& destination, CryptoContext& cryptoContext);
  void saveVersion(Common::IOutputStream& destination);
  void saveWallets(Common::IOutputStream& destination, bool saveCache, CryptoContext& cryptoContext);
  void subscribeWallets();
  void updateTransactionsBaseStatus();
  void updateTransfersSign();

  ITransfersObserver& m_transfersObserver;
  Crypto::PublicKey& m_viewPublicKey;
  Crypto::SecretKey& m_viewPrivateKey;
  uint64_t& m_actualBalance;
  uint64_t& m_pendingBalance;
  WalletsContainer& m_walletsContainer;
  TransfersSyncronizer& m_transfersSynchronizer;
  UnlockTransactionJobs& m_unlockTransactions;
  WalletTransactions& m_walletTransactions;
  WalletTransfers& m_walletTransfers;
  uint32_t m_transactionSoftLockTime;
  UncommitedTransactions& m_uncommitedTransactions;
};

} // end namespace CryptoNote
