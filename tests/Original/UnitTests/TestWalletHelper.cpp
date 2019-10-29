// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <algorithm>
#include <queue>
#include <system_error>

#include <IWallet.h>

#include "CryptoNoteCore/Currency.h"
#include "Logging/LoggerGroup.h"
#include "Logging/ConsoleLogger.h"
#include <System/Event.h>
#include "PaymentGateService/WalletHelper.h"
#include "PaymentGateService/WalletHelperErrors.h"
#include "INodeStubs.h"
#include "Wallet/WalletErrors.h"

using namespace CryptoNote;
using namespace Walletd;

namespace CryptoNote {

bool operator== (const WalletOrder& lhs, const WalletOrder& rhs) {
  return std::make_tuple(lhs.address, lhs.amount) == std::make_tuple(rhs.address, rhs.amount);
}

bool operator== (const DonationSettings& lhs, const DonationSettings& rhs) {
  return std::make_tuple(lhs.address, lhs.threshold) == std::make_tuple(rhs.address, rhs.threshold);
}

} //namespace CryptoNote

struct IWalletBaseStub : public CryptoNote::IWallet {
  IWalletBaseStub(System::Dispatcher& dispatcher) : m_eventOccurred(dispatcher) {}
  virtual ~IWalletBaseStub() {}

  virtual void initialize(const std::string& password) override { }
  virtual void initializeWithViewKey(const Crypto::SecretKey& viewSecretKey, const std::string& password) override { }
  virtual void load(std::istream& source, const std::string& password) override { }
  virtual void shutdown() override { }

  virtual void changePassword(const std::string& oldPassword, const std::string& newPassword) override { }
  virtual void save(std::ostream& destination, bool saveDetails = true, bool saveCache = true) override { }

  virtual size_t getAddressCount() const override { return 0; }
  virtual std::string getAddress(size_t index) const override { return ""; }
  virtual KeyPair getAddressSpendKey(size_t index) const override { return KeyPair(); }
  virtual KeyPair getAddressSpendKey(const std::string& address) const override { return KeyPair(); }
  virtual KeyPair getViewKey() const override { return KeyPair(); }
  virtual std::string createAddress() override { return ""; }
  virtual std::string createAddress(const Crypto::SecretKey& spendSecretKey) override { return ""; }
  virtual std::string createAddress(const Crypto::PublicKey& spendPublicKey) override { return ""; }
  virtual void deleteAddress(const std::string& address) override { }

  virtual uint64_t getActualBalance() const override { return 0; }
  virtual uint64_t getActualBalance(const std::string& address) const override { return 0; }
  virtual uint64_t getPendingBalance() const override { return 0; }
  virtual uint64_t getPendingBalance(const std::string& address) const override { return 0; }

  virtual size_t getTransactionCount() const override { return 0; }
  virtual WalletTransaction getTransaction(size_t transactionIndex) const override { return WalletTransaction(); }

  virtual Crypto::SecretKey getTransactionSecretKey(size_t transactionIndex) const override { return CryptoNote::NULL_SECRET_KEY; }

  virtual size_t getTransactionTransferCount(size_t transactionIndex) const override { return 0; }
  virtual WalletTransfer getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const override { return WalletTransfer(); }

  virtual WalletTransactionWithTransfers getTransaction(const Crypto::Hash& transactionHash) const override { return WalletTransactionWithTransfers(); }
  virtual std::vector<TransactionsInBlockInfo> getTransactions(const Crypto::Hash& blockHash, size_t count) const override { return {}; }
  virtual std::vector<TransactionsInBlockInfo> getTransactions(uint32_t blockIndex, size_t count) const override { return {}; }
  virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t blockIndex, size_t count) const override { return {}; }
  virtual uint32_t getBlockCount() const override { return 0; }
  virtual std::vector<WalletTransactionWithTransfers> getUnconfirmedTransactions() const override { return {}; }
  virtual std::vector<size_t> getDelayedTransactionIds() const override { return {}; }

  virtual size_t transfer(const TransactionParameters& sendingTransaction, Crypto::SecretKey& txSecretKey) override { return 0; }

  virtual size_t makeTransaction(const TransactionParameters& sendingTransaction) override { return 0; }
  virtual void commitTransaction(size_t transactionId) override { }
  virtual void rollbackUncommitedTransaction(size_t transactionId) override { }

  virtual void start() override { m_stopped = false; }
  virtual void stop() override { m_stopped = true; m_eventOccurred.set(); }

  //blocks until an event occurred
  virtual WalletEvent getEvent() override {
    throwIfStopped();

    while(m_events.empty()) {
      m_eventOccurred.wait();
      m_eventOccurred.clear();
      throwIfStopped();
    }

    WalletEvent event = std::move(m_events.front());
    m_events.pop();

    return event;
  }

  void pushEvent(const WalletEvent& event) {
    m_events.push(event);
    m_eventOccurred.set();
  }

protected:
  void throwIfStopped() {
    if (m_stopped) {
      throw std::system_error(make_error_code(std::errc::operation_canceled));
    }
  }

  bool m_stopped = false;
  System::Event m_eventOccurred;
  std::queue<WalletEvent> m_events;
};

class WalletHelperTest: public ::testing::Test {
public:
  WalletHelperTest() :
    currency(CryptoNote::CurrencyBuilder(logger).currency()),
    generator(currency),
    nodeStub(generator),
    walletBase(dispatcher)
  {}

  virtual void SetUp() override;
protected:
  Logging::ConsoleLogger logger;
  Currency currency;
  TestBlockchainGenerator generator;
  INodeTrivialRefreshStub nodeStub;
  WalletConfiguration walletConfig;
  System::Dispatcher dispatcher;
  IWalletBaseStub walletBase;

  std::unique_ptr<WalletHelper> createWalletHelper(CryptoNote::IWallet& wallet);
  std::unique_ptr<WalletHelper> createWalletHelper();
  Crypto::Hash generateRandomHash();
};

void WalletHelperTest::SetUp() {
  logger.setMaxLevel(Logging::DEBUGGING);

  walletConfig.walletFile = "test";
  walletConfig.walletPassword = "test";
}

std::unique_ptr<WalletHelper> WalletHelperTest::createWalletHelper(CryptoNote::IWallet& wallet) {
  return std::unique_ptr<WalletHelper> (new WalletHelper(currency, dispatcher, nodeStub, wallet, walletConfig, logger));
}

std::unique_ptr<WalletHelper> WalletHelperTest::createWalletHelper() {
  return createWalletHelper(walletBase);
}

Crypto::Hash WalletHelperTest::generateRandomHash() {
  Crypto::Hash hash;
  std::generate(std::begin(hash.data), std::end(hash.data), std::rand);
  return hash;
}

class WalletHelperTest_createAddress : public WalletHelperTest {
};

struct WalletCreateAddressStub: public IWalletBaseStub {
  WalletCreateAddressStub(System::Dispatcher& d) : IWalletBaseStub(d) {}

  virtual std::string createAddress() override { return address; }
  virtual std::string createAddress(const Crypto::SecretKey& spendSecretKey) override { return address; }
  virtual std::string createAddress(const Crypto::PublicKey& spendPublicKey) override { return address; }

  std::string address = "correctAddress";
};

TEST_F(WalletHelperTest_createAddress, returnsCorrectAddress) {
  WalletCreateAddressStub wallet(dispatcher);

  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);
  std::string address;
  std::error_code ec = walletHelper->createAddress(address);

  ASSERT_FALSE(ec);
  ASSERT_EQ(wallet.address, address);
}

TEST_F(WalletHelperTest_createAddress, invalidSecretKey) {
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper();

  std::string address;
  std::error_code ec = walletHelper->createAddress("wrong key", address);
  ASSERT_EQ(make_error_code(CryptoNote::error::WalletHelperErrorCode::WRONG_KEY_FORMAT), ec);
}

TEST_F(WalletHelperTest_createAddress, invalidPublicKey) {
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper();

  std::string address;
  std::error_code ec = walletHelper->createTrackingAddress("wrong key", address);
  ASSERT_EQ(make_error_code(CryptoNote::error::WalletHelperErrorCode::WRONG_KEY_FORMAT), ec);
}

TEST_F(WalletHelperTest_createAddress, correctSecretKey) {
  Crypto::PublicKey pub;
  Crypto::SecretKey sec;
  Crypto::generate_keys(pub, sec);

  WalletCreateAddressStub wallet(dispatcher);
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);

  std::string address;
  std::error_code ec = walletHelper->createAddress(Common::podToHex(sec), address);

  ASSERT_FALSE(ec);
  ASSERT_EQ(wallet.address, address);
}

TEST_F(WalletHelperTest_createAddress, correctPublicKey) {
  Crypto::PublicKey pub;
  Crypto::SecretKey sec;
  Crypto::generate_keys(pub, sec);

  WalletCreateAddressStub wallet(dispatcher);
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);

  std::string address;
  std::error_code ec = walletHelper->createTrackingAddress(Common::podToHex(pub), address);

  ASSERT_FALSE(ec);
  ASSERT_EQ(wallet.address, address);
}

class WalletHelperTest_getSpendPrivateKey : public WalletHelperTest {
};

struct WalletGetSpendPrivateKeyStub: public IWalletBaseStub {
  WalletGetSpendPrivateKeyStub(System::Dispatcher& d) : IWalletBaseStub(d) {
    Crypto::generate_keys(keyPair.publicKey, keyPair.secretKey);
  }

  virtual KeyPair getAddressSpendKey(const std::string& address) const override {
    return keyPair;
  }

  KeyPair keyPair;
};

TEST_F(WalletHelperTest_getSpendPrivateKey, returnsKeysCorrectly) {
  WalletGetSpendPrivateKeyStub wallet(dispatcher);
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);

  std::string secretSpendKey;
  auto ec = walletHelper->getSpendPrivateKey("address", secretSpendKey);
  ASSERT_FALSE(ec);
  ASSERT_EQ(Common::podToHex(wallet.keyPair.secretKey), secretSpendKey);
}

class WalletHelperTest_getBalance : public WalletHelperTest {
};

struct WalletGetBalanceStub: public IWalletBaseStub {
  WalletGetBalanceStub(System::Dispatcher& d, bool byAddress) : IWalletBaseStub(d), byAddress(byAddress) {
  }

  virtual uint64_t getActualBalance() const override {
    if (byAddress) {
      throw std::runtime_error("wrong overload");
    }

    return actualBalance;
  }

  virtual uint64_t getPendingBalance() const override {
    if (byAddress) {
      throw std::runtime_error("wrong overload");
    }

    return pendingBalance;
  }

  virtual uint64_t getActualBalance(const std::string& address) const override {
    if (!byAddress) {
      throw std::runtime_error("wrong overload");
    }

    return actualBalance;
  }

  virtual uint64_t getPendingBalance(const std::string& address) const override {
    if (!byAddress) {
      throw std::runtime_error("wrong overload");
    }

    return pendingBalance;
  }

  bool byAddress;
  uint64_t actualBalance = 345466;
  uint64_t pendingBalance = 12121;
};

TEST_F(WalletHelperTest_getBalance, returnsCorrectBalance) {
  WalletGetBalanceStub wallet(dispatcher, false);
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);

  uint64_t actual;
  uint64_t pending;
  auto ec = walletHelper->getBalance(actual, pending);

  ASSERT_FALSE(ec);
  ASSERT_EQ(wallet.actualBalance, actual);
  ASSERT_EQ(wallet.pendingBalance, pending);
}

TEST_F(WalletHelperTest_getBalance, returnsCorrectBalanceByAddress) {
  WalletGetBalanceStub wallet(dispatcher, true);
  std::unique_ptr<WalletHelper> walletHelper = createWalletHelper(wallet);

  uint64_t actual;
  uint64_t pending;
  auto ec = walletHelper->getBalance("address", actual, pending);

  ASSERT_FALSE(ec);
  ASSERT_EQ(wallet.actualBalance, actual);
  ASSERT_EQ(wallet.pendingBalance, pending);
}

class WalletHelperTest_getBlockHashes : public WalletHelperTest {
protected:
  std::vector<Crypto::Hash> convertBlockHashes(const std::vector<std::string>& hashes) {
    std::vector<Crypto::Hash> result;
    result.reserve(hashes.size());

    std::for_each(hashes.begin(), hashes.end(), [&result] (const std::string& str) {
      Crypto::Hash hash;
      Common::podFromHex(str, hash);
      result.push_back(hash);
    });

    return result;
  }
};

struct WalletGetBlockHashesStub: public IWalletBaseStub {
  WalletGetBlockHashesStub(System::Dispatcher& d) : IWalletBaseStub(d) {
  }

  virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t blockIndex, size_t count) const override {
    return blockHashes;
  }

  std::vector<Crypto::Hash> blockHashes;
};

TEST_F(WalletHelperTest_getBlockHashes, returnsEmptyBlockHashes) {
  WalletGetBlockHashesStub wallet(dispatcher);
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> blockHashes;
  ASSERT_FALSE(walletHelper->getBlockHashes(0, 1, blockHashes));
  ASSERT_EQ(wallet.blockHashes, convertBlockHashes(blockHashes));
}

TEST_F(WalletHelperTest_getBlockHashes, returnsBlockHashes) {
  WalletGetBlockHashesStub wallet(dispatcher);
  std::generate_n(std::back_inserter(wallet.blockHashes), 10, [this] () { return generateRandomHash(); });
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> blockHashes;
  ASSERT_FALSE(walletHelper->getBlockHashes(0, 10, blockHashes));
  ASSERT_EQ(wallet.blockHashes, convertBlockHashes(blockHashes));
}

class WalletHelperTest_getViewKey : public WalletHelperTest {
};

struct WalletGetViewKeyStub: public IWalletBaseStub {
  WalletGetViewKeyStub(System::Dispatcher& d) : IWalletBaseStub(d) {
    Crypto::generate_keys(keyPair.publicKey, keyPair.secretKey);
  }

  virtual KeyPair getViewKey() const override {
    return keyPair;
  }

  KeyPair keyPair;
};

TEST_F(WalletHelperTest_getViewKey, returnsCorrectValue) {
  WalletGetViewKeyStub wallet(dispatcher);
  auto walletHelper = createWalletHelper(wallet);

  std::string viewSecretKey;
  ASSERT_FALSE(walletHelper->getViewPrivateKey(viewSecretKey));
  ASSERT_EQ(Common::podToHex(wallet.keyPair.secretKey), viewSecretKey);
}

class WalletTransactionBuilder {
public:
  WalletTransactionBuilder& hash(const Crypto::Hash& hash) {
    transaction.hash = hash;
    return *this;
  }

  WalletTransactionBuilder& extra(const std::string& extra) {
    transaction.extra = Common::asString(Common::fromHex(extra));
    return *this;
  }

  WalletTransactionBuilder& state(WalletTransactionState state) {
    transaction.state = state;
    return *this;
  }

  WalletTransaction build() const {
    return transaction;
  }

  WalletTransactionBuilder& timestamp(uint64_t t) {
    transaction.timestamp = t;
    return *this;
  }

  WalletTransactionBuilder& blockHeight(uint32_t height) {
    transaction.blockHeight = height;
    return *this;
  }

  WalletTransactionBuilder& totalAmount(int64_t amount) {
    transaction.totalAmount = amount;
    return *this;
  }

  WalletTransactionBuilder& fee(uint64_t fee) {
    transaction.fee = fee;
    return *this;
  }

  WalletTransactionBuilder& creationTime(uint64_t t) {
    transaction.creationTime = t;
    return *this;
  }

  WalletTransactionBuilder& unlockTime(uint64_t unlock) {
    transaction.unlockTime = unlock;
    return *this;
  }

  WalletTransactionBuilder& isBase(bool base) {
    transaction.isBase = base;
    return *this;
  }

private:
  WalletTransaction transaction;
};

class WalletTransactionWithTransfersBuilder {
public:
  WalletTransactionWithTransfersBuilder& transaction(const WalletTransaction& transaction) {
    tx.transaction = transaction;
    return *this;
  }

  WalletTransactionWithTransfersBuilder& addTransfer(const std::string& address, int64_t amount) {
    tx.transfers.push_back(WalletTransfer{WalletTransferType::USUAL, address, amount});
    return *this;
  }

  WalletTransactionWithTransfers build() const {
    return tx;
  }

private:
  WalletTransactionWithTransfers tx;
};

class WalletHelperTest_getTransactions : public WalletHelperTest {
  virtual void SetUp() override;
protected:
  std::vector<TransactionsInBlockInfo> testTransactions;
  const std::string RANDOM_ADDRESS1 = "26oKBqjiD5rj3znnRUcwsuHQRZbxwJdMMQ8N9XSTAUtx14SeHtoSKw9fvLzYjqz4AmT7LDyJ1YT2mUdwmmNqrjVc5SiJ62g";
  const std::string RANDOM_ADDRESS2 = "21L4AmFtfJjWRkJ33NZjn7MNVX3dSjJdRZGMww5tQLXGDR5Vy84s9GXSEzVB5f2NS2inM5TfxzcvpHNxSKycynjbRwjnLph";
  const std::string RANDOM_ADDRESS3 = "23a2ABFzLMQNsEh8TLoBZ1hUHa8LCwZto7duUGwejufg5Y5ia9yG7FsYFbWZHHirE9ChjqcB81djTUsqMsb7SujgPW5nEnH";
  const std::string TRANSACTION_EXTRA = "022100dededededededededededededededededededededededededededededededede";
  const std::string PAYMENT_ID = "dededededededededededededededededededededededededededededededede";
};

void WalletHelperTest_getTransactions::SetUp() {
  TransactionsInBlockInfo block;
  block.blockHash = generateRandomHash();
  block.transactions.push_back(
    WalletTransactionWithTransfersBuilder().addTransfer(RANDOM_ADDRESS1, 222).addTransfer(RANDOM_ADDRESS2, 33333).transaction(
          WalletTransactionBuilder().hash(generateRandomHash()).extra(TRANSACTION_EXTRA).build()
    ).build()
  );

  testTransactions.push_back(block);
}

class WalletGetTransactionsStub : public IWalletBaseStub {
public:
  WalletGetTransactionsStub(System::Dispatcher& d) : IWalletBaseStub(d) {}
  virtual std::vector<TransactionsInBlockInfo> getTransactions(const Crypto::Hash& blockHash, size_t count) const override {
    return transactions;
  }

  virtual std::vector<TransactionsInBlockInfo> getTransactions(uint32_t blockIndex, size_t count) const override {
    return transactions;
  }

  std::vector<TransactionsInBlockInfo> transactions;
};

TEST_F(WalletHelperTest_getTransactions, addressesFilter_emptyReturnsTransaction) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({}, 0, 1, "", transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(Common::podToHex(testTransactions[0].transactions[0].transaction.hash), transactions[0].transactions[0].transaction_hash);
}

TEST_F(WalletHelperTest_getTransactions, addressesFilter_existentReturnsTransaction) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({RANDOM_ADDRESS1}, 0, 1, "", transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(Common::podToHex(testTransactions[0].transactions[0].transaction.hash), transactions[0].transactions[0].transaction_hash);
}

TEST_F(WalletHelperTest_getTransactions, addressesFilter_nonExistentReturnsNoTransactions) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({RANDOM_ADDRESS3}, 0, 1, "", transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(0, transactions.size());
}

TEST_F(WalletHelperTest_getTransactions, addressesFilter_existentAndNonExistentReturnsTransaction) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({RANDOM_ADDRESS1, RANDOM_ADDRESS3}, 0, 1, "", transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(Common::podToHex(testTransactions[0].transactions[0].transaction.hash), transactions[0].transactions[0].transaction_hash);
}

TEST_F(WalletHelperTest_getTransactions, paymentIdFilter_existentReturnsTransaction) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({}, 0, 1, PAYMENT_ID, transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(Common::podToHex(testTransactions[0].transactions[0].transaction.hash), transactions[0].transactions[0].transaction_hash);
  ASSERT_EQ(PAYMENT_ID, transactions[0].transactions[0].payment_id);
}

TEST_F(WalletHelperTest_getTransactions, paymentIdFilter_nonExistentReturnsNoTransaction) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({}, 0, 1, "dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf", transactions);

  ASSERT_FALSE(ec);

  ASSERT_EQ(0, transactions.size());
}

TEST_F(WalletHelperTest_getTransactions, invalidAddress) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({"invalid address"}, 0, 1, "", transactions);
  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}

TEST_F(WalletHelperTest_getTransactions, invalidPaymentId) {
  WalletGetTransactionsStub wallet(dispatcher);
  wallet.transactions = testTransactions;

  auto walletHelper = createWalletHelper(wallet);

  std::vector<TransactionsInBlockRpcInfo> transactions;
  auto ec = walletHelper->getTransactions({}, 0, 1, "invalid payment id", transactions);
  ASSERT_EQ(make_error_code(CryptoNote::error::WalletHelperErrorCode::WRONG_PAYMENT_ID_FORMAT), ec);
}

TEST_F(WalletHelperTest_getTransactions, blockNotFound) {
  WalletGetTransactionsStub wallet(dispatcher);
  auto walletHelper = createWalletHelper(wallet);
  std::vector<TransactionsInBlockRpcInfo> transactions;

  auto ec = walletHelper->getTransactions({}, 0, 1, "", transactions);
  ASSERT_EQ(make_error_code(CryptoNote::error::WalletHelperErrorCode::OBJECT_NOT_FOUND), ec);
}

class WalletHelperTest_getTransaction : public WalletHelperTest_getTransactions {
};

struct WalletGetTransactionStub : public IWalletBaseStub {
  WalletGetTransactionStub (System::Dispatcher& dispatcher) : IWalletBaseStub(dispatcher) {
  }

  virtual WalletTransactionWithTransfers getTransaction(const Crypto::Hash& transactionHash) const override {
    return transaction;
  }

  WalletTransactionWithTransfers transaction;
};

TEST_F(WalletHelperTest_getTransaction, wrongHash) {
  auto walletHelper = createWalletHelper();

  TransactionRpcInfo transaction;
  auto ec = walletHelper->getTransaction("wrong hash", transaction);
  ASSERT_EQ(make_error_code(CryptoNote::error::WalletHelperErrorCode::WRONG_HASH_FORMAT), ec);
}

TEST_F(WalletHelperTest_getTransaction, returnsCorrectFields) {
  WalletGetTransactionStub wallet(dispatcher);
  wallet.transaction = WalletTransactionWithTransfersBuilder().transaction(
        WalletTransactionBuilder()
        .state(WalletTransactionState::FAILED)
        .hash(generateRandomHash())
        .creationTime(789123)
        .extra(TRANSACTION_EXTRA)
        .fee(293945)
        .isBase(false)
        .timestamp(929293847)
        .totalAmount(-200000)
        .unlockTime(23456)
        .build()
    ).addTransfer("address1", 231).addTransfer("address2", 883).build();

  auto walletHelper = createWalletHelper(wallet);

  TransactionRpcInfo transaction;
  auto ec = walletHelper->getTransaction(Common::podToHex(Crypto::Hash()), transaction);

  ASSERT_FALSE(ec);
  ASSERT_EQ(static_cast<uint8_t>(wallet.transaction.transaction.state), transaction.state);
  ASSERT_EQ(wallet.transaction.transaction.blockHeight, transaction.block_index);
  ASSERT_EQ(Common::toHex(Common::asBinaryArray(wallet.transaction.transaction.extra)), transaction.extra);
  ASSERT_EQ(PAYMENT_ID, transaction.payment_id);
  ASSERT_EQ(wallet.transaction.transaction.fee, transaction.fee);
  ASSERT_EQ(wallet.transaction.transaction.isBase, transaction.is_base);
  ASSERT_EQ(wallet.transaction.transaction.timestamp, transaction.timestamp);
  ASSERT_EQ(Common::podToHex(wallet.transaction.transaction.hash), transaction.transaction_hash);
  ASSERT_EQ(wallet.transaction.transaction.unlockTime, transaction.unlock_time);

  ASSERT_EQ(wallet.transaction.transfers.size(), transaction.transfers.size());

  ASSERT_EQ(wallet.transaction.transfers[0].address, transaction.transfers[0].address);
  ASSERT_EQ(wallet.transaction.transfers[0].amount, transaction.transfers[0].amount);

  ASSERT_EQ(wallet.transaction.transfers[1].address, transaction.transfers[1].address);
  ASSERT_EQ(wallet.transaction.transfers[1].amount, transaction.transfers[1].amount);

}

struct WalletGetTransactionThrowStub : public IWalletBaseStub {
  WalletGetTransactionThrowStub (System::Dispatcher& dispatcher) : IWalletBaseStub(dispatcher) {
  }

  virtual WalletTransactionWithTransfers getTransaction(const Crypto::Hash& transactionHash) const override {
    throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
  }
};

TEST_F(WalletHelperTest_getTransaction, transactionNotFound) {
  WalletGetTransactionThrowStub wallet(dispatcher);
  auto walletHelper = createWalletHelper(wallet);

  TransactionRpcInfo transaction;
  auto ec = walletHelper->getTransaction(Common::podToHex(Crypto::Hash()), transaction);

  ASSERT_EQ(make_error_code(error::OBJECT_NOT_FOUND), ec);
}

class WalletHelperTest_sendTransaction : public WalletHelperTest_getTransactions {
  virtual void SetUp() override;
protected:
  WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request request;
};

void WalletHelperTest_sendTransaction::SetUp() {
  request.source_addresses.insert(request.source_addresses.end(), {RANDOM_ADDRESS1, RANDOM_ADDRESS2});
  request.transfers.push_back(WalletRpcOrder {RANDOM_ADDRESS3, 11111});
  request.fee = 2021;
  request.anonymity = 3;
  request.unlock_time = 848309;
}

struct WalletTransferStub : public IWalletBaseStub {
  WalletTransferStub(System::Dispatcher& dispatcher, const Crypto::Hash& hash) : IWalletBaseStub(dispatcher), hash(hash) {
  }

  virtual size_t transfer(const TransactionParameters& sendingTransaction, Crypto::SecretKey& txSecretKey) override {
    params = sendingTransaction;
    return 0;
  }

  virtual WalletTransaction getTransaction(size_t transactionIndex) const override {
    return WalletTransactionBuilder().hash(hash).build();
  }

  Crypto::Hash hash;
  TransactionParameters params;
};

bool isEquivalent(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, const TransactionParameters& params) {
  std::string extra;
  if (!request.payment_id.empty()) {
    extra = "022100" + request.payment_id;
  } else {
    extra = request.extra;
  }

  std::vector<WalletOrder> orders;
  std::for_each(request.transfers.begin(), request.transfers.end(), [&orders] (const WalletRpcOrder& order) {
    orders.push_back( WalletOrder{order.address, order.amount});
  });

  return std::make_tuple(request.source_addresses, orders, request.fee, request.anonymity, extra, request.unlock_time)
      ==
      std::make_tuple(params.sourceAddresses, params.destinations, params.fee, params.mixIn, Common::toHex(Common::asBinaryArray(params.extra)), params.unlockTimestamp);
}

TEST_F(WalletHelperTest_sendTransaction, passesCorrectParameters) {
  WalletTransferStub wallet(dispatcher, generateRandomHash());
  auto walletHelper = createWalletHelper(wallet);

  std::string hash;
  std::string transactionSecretKey;
  auto ec = walletHelper->sendTransaction(request, hash, transactionSecretKey);

  ASSERT_FALSE(ec);
  ASSERT_EQ(Common::podToHex(wallet.hash), hash);
  ASSERT_TRUE(isEquivalent(request, wallet.params));
}

TEST_F(WalletHelperTest_sendTransaction, incorrectSourceAddress) {
  auto walletHelper = createWalletHelper();
  request.source_addresses.push_back("wrong address");

  std::string hash;
  std::string transactionSecretKey;
  auto ec = walletHelper->sendTransaction(request, hash, transactionSecretKey);
  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}

TEST_F(WalletHelperTest_sendTransaction, incorrectTransferAddress) {
  auto walletHelper = createWalletHelper();
  request.transfers.push_back(WalletRpcOrder{"wrong address", 12131});

  std::string hash;
  std::string transactionSecretKey;
  auto ec = walletHelper->sendTransaction(request, hash, transactionSecretKey);
  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}

class WalletHelperTest_createDelayedTransaction : public WalletHelperTest_getTransactions {
  virtual void SetUp() override;
protected:
  WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request request;
};

void WalletHelperTest_createDelayedTransaction::SetUp() {
  request.addresses.insert(request.addresses.end(), {RANDOM_ADDRESS1, RANDOM_ADDRESS2});
  request.transfers.push_back(WalletRpcOrder {RANDOM_ADDRESS3, 11111});
  request.fee = 2021;
  request.anonymity = 4;
  request.unlock_time = 848309;
}

struct WalletMakeTransactionStub : public IWalletBaseStub {
  WalletMakeTransactionStub(System::Dispatcher& dispatcher, const Crypto::Hash& hash) : IWalletBaseStub(dispatcher), hash(hash) {
  }

  virtual size_t makeTransaction(const TransactionParameters& sendingTransaction) override {
    params = sendingTransaction;
    return 0;
  }

  virtual WalletTransaction getTransaction(size_t transactionIndex) const override {
    return WalletTransactionBuilder().hash(hash).build();
  }

  Crypto::Hash hash;
  TransactionParameters params;
};

bool isEquivalent(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, const TransactionParameters& params) {
  std::string extra;
  if (!request.payment_id.empty()) {
    extra = "022100" + request.payment_id;
  } else {
    extra = request.extra;
  }

  std::vector<WalletOrder> orders;
  std::for_each(request.transfers.begin(), request.transfers.end(), [&orders] (const WalletRpcOrder& order) {
    orders.push_back( WalletOrder{order.address, order.amount});
  });

  return std::make_tuple(request.addresses, orders, request.fee, request.anonymity, extra, request.unlock_time)
      ==
      std::make_tuple(params.sourceAddresses, params.destinations, params.fee, params.mixIn, Common::toHex(Common::asBinaryArray(params.extra)), params.unlockTimestamp);
}

TEST_F(WalletHelperTest_createDelayedTransaction, passesCorrectParameters) {
  WalletMakeTransactionStub wallet(dispatcher, generateRandomHash());
  auto walletHelper = createWalletHelper(wallet);

  std::string hash;
  auto ec = walletHelper->createDelayedTransaction(request, hash);

  ASSERT_FALSE(ec);
  ASSERT_EQ(Common::podToHex(wallet.hash), hash);
  ASSERT_TRUE(isEquivalent(request, wallet.params));
}

TEST_F(WalletHelperTest_createDelayedTransaction, incorrectSourceAddress) {
  auto walletHelper = createWalletHelper();
  request.addresses.push_back("wrong address");

  std::string hash;
  auto ec = walletHelper->createDelayedTransaction(request, hash);
  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}

TEST_F(WalletHelperTest_createDelayedTransaction, incorrectTransferAddress) {
  auto walletHelper = createWalletHelper();
  request.transfers.push_back(WalletRpcOrder{"wrong address", 12131});

  std::string hash;
  auto ec = walletHelper->createDelayedTransaction(request, hash);
  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}

class WalletHelperTest_getDelayedTransactionHashes: public WalletHelperTest {
};

struct WalletGetDelayedTransactionIdsStub : public IWalletBaseStub {
  WalletGetDelayedTransactionIdsStub(System::Dispatcher& dispatcher, const Crypto::Hash& hash) : IWalletBaseStub(dispatcher), hash(hash) {
  }

  virtual std::vector<size_t> getDelayedTransactionIds() const override {
    return {0};
  }

  virtual WalletTransaction getTransaction(size_t transactionIndex) const override {
    return WalletTransactionBuilder().hash(hash).build();
  }

  const Crypto::Hash hash;
};

TEST_F(WalletHelperTest_getDelayedTransactionHashes, returnsCorrectResult) {
  WalletGetDelayedTransactionIdsStub wallet(dispatcher, generateRandomHash());
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> hashes;
  auto ec = walletHelper->getDelayedTransactionHashes(hashes);

  ASSERT_FALSE(ec);
  ASSERT_EQ(1, hashes.size());
  ASSERT_EQ(Common::podToHex(wallet.hash), hashes[0]);
}

class WalletHelperTest_getUnconfirmedTransactionHashes: public WalletHelperTest_getTransactions {
public:
  virtual void SetUp() override;
protected:
  std::vector<CryptoNote::WalletTransactionWithTransfers> transactions;
};

void WalletHelperTest_getUnconfirmedTransactionHashes::SetUp() {
  transactions = { WalletTransactionWithTransfersBuilder().transaction(
                    WalletTransactionBuilder().hash(generateRandomHash()).build()
                   ).addTransfer(RANDOM_ADDRESS1, 100).addTransfer(RANDOM_ADDRESS2, 333).build()
                  ,
                   WalletTransactionWithTransfersBuilder().transaction(
                     WalletTransactionBuilder().hash(generateRandomHash()).build()
                   ).addTransfer(RANDOM_ADDRESS3, 123).addTransfer(RANDOM_ADDRESS2, 4252).build()
  };
}

struct WalletGetUnconfirmedTransactionsStub : public IWalletBaseStub {
  WalletGetUnconfirmedTransactionsStub(System::Dispatcher& dispatcher) : IWalletBaseStub(dispatcher) {
  }

  virtual std::vector<WalletTransactionWithTransfers> getUnconfirmedTransactions() const override {
    return transactions;
  }

  std::vector<CryptoNote::WalletTransactionWithTransfers> transactions;
};

TEST_F(WalletHelperTest_getUnconfirmedTransactionHashes, returnsAllHashesWithoutAddresses) {
  WalletGetUnconfirmedTransactionsStub wallet(dispatcher);
  wallet.transactions = transactions;
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> hashes;
  auto ec = walletHelper->getUnconfirmedTransactionHashes({}, hashes);

  ASSERT_FALSE(ec);
  ASSERT_EQ(2, hashes.size());
  ASSERT_EQ(hashes[0], Common::podToHex(transactions[0].transaction.hash));
  ASSERT_EQ(hashes[1], Common::podToHex(transactions[1].transaction.hash));
}

TEST_F(WalletHelperTest_getUnconfirmedTransactionHashes, returnsOneTransactionWithAddressFilter) {
  WalletGetUnconfirmedTransactionsStub wallet(dispatcher);
  wallet.transactions = transactions;
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> hashes;
  auto ec = walletHelper->getUnconfirmedTransactionHashes({RANDOM_ADDRESS1}, hashes);

  ASSERT_FALSE(ec);
  ASSERT_EQ(1, hashes.size());
  ASSERT_EQ(hashes[0], Common::podToHex(transactions[0].transaction.hash));
}

TEST_F(WalletHelperTest_getUnconfirmedTransactionHashes, returnsTwoTransactionsWithAddressFilter) {
  WalletGetUnconfirmedTransactionsStub wallet(dispatcher);
  wallet.transactions = transactions;
  auto walletHelper = createWalletHelper(wallet);

  std::vector<std::string> hashes;
  auto ec = walletHelper->getUnconfirmedTransactionHashes({RANDOM_ADDRESS2}, hashes);

  ASSERT_FALSE(ec);
  ASSERT_EQ(2, hashes.size());
  ASSERT_EQ(hashes[0], Common::podToHex(transactions[0].transaction.hash));
  ASSERT_EQ(hashes[1], Common::podToHex(transactions[1].transaction.hash));
}

TEST_F(WalletHelperTest_getUnconfirmedTransactionHashes, wrongAddressFilter) {
  auto walletHelper = createWalletHelper();

  std::vector<std::string> hashes;
  auto ec = walletHelper->getUnconfirmedTransactionHashes({"wrong address"}, hashes);

  ASSERT_EQ(make_error_code(CryptoNote::error::BAD_ADDRESS), ec);
}
