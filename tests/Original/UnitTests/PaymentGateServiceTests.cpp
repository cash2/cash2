// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include <numeric>

#include <System/Timer.h>
#include <Common/StringTools.h>
#include <Logging/ConsoleLogger.h>

#include "PaymentGateService/WalletHelper.h"
#include "Wallet/WalletGreen.h"

// test helpers
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"

using namespace Walletd;
using namespace CryptoNote;

class PaymentGateServiceTest : public testing::Test {
public:

  PaymentGateServiceTest() : 
    currency(CryptoNote::CurrencyBuilder(logger).currency()), 
    generator(currency),
    nodeStub(generator) 
  {}

  WalletConfiguration createWalletConfiguration(const std::string& walletFile = "pgwalleg.bin") const {
    return WalletConfiguration{ walletFile, "pass" };
  }

  std::unique_ptr<WalletHelper> createWalletHelper(const WalletConfiguration& cfg) {
    wallet.reset(new CryptoNote::WalletGreen(dispatcher, currency, nodeStub));
    std::unique_ptr<WalletHelper> walletHelper(new WalletHelper(currency, dispatcher, nodeStub, *wallet, cfg, logger));
    walletHelper->init();
    return walletHelper;
  }

  void generateWallet(const WalletConfiguration& conf) {
    unlink(conf.walletFile.c_str());
    generateNewWallet(currency, conf, logger, dispatcher);
  }

protected:  
  Logging::ConsoleLogger logger;
  CryptoNote::Currency currency;
  TestBlockchainGenerator generator;
  INodeTrivialRefreshStub nodeStub;
  System::Dispatcher dispatcher;

  std::unique_ptr<CryptoNote::IWallet> wallet;
};


TEST_F(PaymentGateServiceTest, createWallet) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto walletHelper = createWalletHelper(cfg);
}

TEST_F(PaymentGateServiceTest, addTransaction) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto walletHelper = createWalletHelper(cfg);

  std::string addressStr;
  ASSERT_TRUE(!walletHelper->createAddress(addressStr));

  AccountPublicAddress address;
  ASSERT_TRUE(currency.parseAccountAddressString(addressStr, address));

  generator.getBlockRewardForAddress(address);
  generator.getBlockRewardForAddress(address);
  generator.generateEmptyBlocks(11);
  generator.getBlockRewardForAddress(address);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(2));

  uint64_t pending = 0, actual = 0;

  walletHelper->getBalance(actual, pending);

  ASSERT_NE(0, pending);
  ASSERT_NE(0, actual);

  ASSERT_EQ(pending * 2, actual);
}

/*
TEST_F(PaymentGateServiceTest, DISABLED_sendTransaction) {

  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto walletHelper = createWalletHelper(cfg);

  std::string addressStr;
  ASSERT_TRUE(!walletHelper->createAddress(addressStr));

  AccountPublicAddress address;
  ASSERT_TRUE(currency.parseAccountAddressString(addressStr, address));

  generator.getBlockRewardForAddress(address);
  generator.generateEmptyBlocks(11);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  auto cfg2 = createWalletConfiguration("pgwallet2.bin");
  generateWallet(cfg2);
  auto walletHelperRecv = createWalletHelper(cfg2);

  std::string recvAddress;
  walletHelperRecv->createAddress(recvAddress);

  uint64_t TEST_AMOUNT = 0;
  currency.parseAmount("100000.0", TEST_AMOUNT);

  Crypto::Hash paymentId;
  std::iota(reinterpret_cast<char*>(&paymentId), reinterpret_cast<char*>(&paymentId) + sizeof(paymentId), 0);
  std::string paymentIdStr = Common::podToHex(paymentId);

  uint64_t txId = 0;

  {
    SendTransaction::Request req;
    SendTransaction::Response res;

    req.transfers.push_back(WalletRpcOrder{ TEST_AMOUNT, recvAddress });
    req.fee = currency.minimumFee();
    req.anonymity = 1;
    req.unlockTime = 0;
    req.paymentId = paymentIdStr;

    ASSERT_TRUE(!walletHelper->sendTransaction(req, res.transactionHash));

    txId = res.transactionId;
  }

  generator.generateEmptyBlocks(11);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  TransactionRpcInfo txInfo;
  bool found = false;

  ASSERT_TRUE(!walletHelper->getTransaction(txId, found, txInfo));
  ASSERT_TRUE(found);

  uint64_t recvTxCount = 0;
  ASSERT_TRUE(!walletHelperRecv->getTransactionsCount(recvTxCount));
  ASSERT_EQ(1, recvTxCount);

  uint64_t sendTxCount = 0;
  ASSERT_TRUE(!walletHelper->getTransactionsCount(sendTxCount));
  ASSERT_EQ(2, sendTxCount); // 1 from mining, 1 transfer

  TransactionRpcInfo recvTxInfo;
  ASSERT_TRUE(!walletHelperRecv->getTransaction(0, found, recvTxInfo));
  ASSERT_TRUE(found);

  ASSERT_EQ(txInfo.hash, recvTxInfo.hash);
  ASSERT_EQ(txInfo.extra, recvTxInfo.extra);
  ASSERT_EQ(-txInfo.totalAmount - currency.minimumFee(), recvTxInfo.totalAmount);
  ASSERT_EQ(txInfo.blockHeight, recvTxInfo.blockHeight);

  {
    // check payments
    WalletHelper::IncomingPayments payments;
    ASSERT_TRUE(!walletHelperRecv->getIncomingPayments({ paymentIdStr }, payments));

    ASSERT_EQ(1, payments.size());

    ASSERT_EQ(paymentIdStr, payments.begin()->first);

    const auto& recvPayment = payments.begin()->second;

    ASSERT_EQ(1, recvPayment.size());

    ASSERT_EQ(txInfo.hash, recvPayment[0].txHash);
    ASSERT_EQ(TEST_AMOUNT, recvPayment[0].amount);
    ASSERT_EQ(txInfo.blockHeight, recvPayment[0].blockHeight);
  }

  // reload walletHelpers

  walletHelper->saveWallet();
  walletHelperRecv->saveWallet();

  walletHelper.reset();
  walletHelperRecv.reset();

  walletHelper = createWalletHelper(cfg);
  walletHelperRecv = createWalletHelper(cfg2);

  recvTxInfo = boost::value_initialized<TransactionRpcInfo>();
  ASSERT_TRUE(!walletHelperRecv->getTransaction(0, found, recvTxInfo));
  ASSERT_TRUE(found);

  ASSERT_EQ(txInfo.hash, recvTxInfo.hash);
  ASSERT_EQ(txInfo.extra, recvTxInfo.extra);
  ASSERT_EQ(-txInfo.totalAmount - currency.minimumFee(), recvTxInfo.totalAmount);
  ASSERT_EQ(txInfo.blockHeight, recvTxInfo.blockHeight);

  // send some money back
  std::reverse(paymentIdStr.begin(), paymentIdStr.end());

  {
    std::string recvAddress;
    walletHelper->createAddress(recvAddress);

    SendTransactionRequest req;
    SendTransactionResponse res;

    req.destinations.push_back(TransferDestination{ TEST_AMOUNT/2, recvAddress });
    req.fee = currency.minimumFee();
    req.mixin = 1;
    req.unlockTime = 0;
    req.paymentId = paymentIdStr;

    ASSERT_TRUE(!walletHelperRecv->sendTransaction(req, res));

    txId = res.transactionId;
  }

  generator.generateEmptyBlocks(11);
  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  ASSERT_TRUE(!walletHelper->getTransactionsCount(recvTxCount));
  ASSERT_EQ(3, recvTxCount);

  {
    WalletHelper::IncomingPayments payments;
    ASSERT_TRUE(!walletHelper->getIncomingPayments({ paymentIdStr }, payments));
    ASSERT_EQ(1, payments.size());
    ASSERT_EQ(paymentIdStr, payments.begin()->first);

    const auto& recvPayment = payments.begin()->second;

    ASSERT_EQ(1, recvPayment.size());
    ASSERT_EQ(TEST_AMOUNT / 2, recvPayment[0].amount);
  }
} */
