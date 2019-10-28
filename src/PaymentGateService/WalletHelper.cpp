// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assert.h>
#include <boost/filesystem/operations.hpp>
#include <future>
#include <sstream>
#include <unordered_set>

#include "Common/ConsoleTools.h"
#include "Common/StringTools.h"
#include "Common/Util.h"
#include "crypto/crypto.h"
#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "NodeFactory.h"
#include "PaymentServiceJsonRpcMessages.h"
#include "System/EventLock.h"
#include "System/InterruptedException.h"
#include "System/Timer.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletGreen.h"
#include "Wallet/WalletUtils.h"
#include "WalletHelper.h"
#include "WalletServiceErrorCategory.h"

namespace PaymentService {

void createWalletFile(std::fstream& walletFile, const std::string& filename)
{
  boost::filesystem::path pathToWalletFile(filename);
  boost::filesystem::path directory = pathToWalletFile.parent_path();
  
  if (!directory.empty() && !Tools::directoryExists(directory.string()))
  {
    throw std::runtime_error("Directory does not exist : " + directory.string());
  }

  walletFile.open(filename.c_str(), std::fstream::in | std::fstream::out | std::fstream::binary);
  
  if (walletFile)
  {
    walletFile.close();
    throw std::runtime_error("Wallet file already exists");
  }

  walletFile.open(filename.c_str(), std::fstream::out);
  walletFile.close();

  walletFile.open(filename.c_str(), std::fstream::in | std::fstream::out | std::fstream::binary);
}

void generateNewWallet(const CryptoNote::Currency &currency, const WalletConfiguration &config, Logging::ILogger& logger, System::Dispatcher& dispatcher)
{
  Logging::LoggerRef log(logger, "Create New Wallet");

  if (config.walletSpendPrivateKey.empty() && config.walletViewPrivateKey.empty())
  {
    // Create new wallet

    log(Logging::INFO) << "Creating a new wallet container ...";

    CryptoNote::INode* nodeStub = NodeFactory::createNodeStub();
    std::unique_ptr<CryptoNote::INode> nodeGuard(nodeStub);

    CryptoNote::IWallet* walletPtr = new CryptoNote::WalletGreen(dispatcher, currency, *nodeStub);
    std::unique_ptr<CryptoNote::IWallet> walletGuard(walletPtr);
    walletPtr->initialize(config.walletPassword);
    std::string address = walletPtr->createAddress();
    CryptoNote::KeyPair spendKeyPair = walletPtr->getAddressSpendKey(address);
    CryptoNote::KeyPair viewKeyPair = walletPtr->getViewKey();

    log(Logging::INFO) << "A new wallet was successfully created :";

    std::string spendSecretKeyStr = Common::podToHex<Crypto::SecretKey>(spendKeyPair.secretKey);
    std::string viewSecretKeyStr = Common::podToHex<Crypto::SecretKey>(viewKeyPair.secretKey);

    Common::Console::setTextColor(Common::Console::Color::BrightCyan);
    std::cout <<
      "Address : " << address <<
      "\nSpend private key : " << spendSecretKeyStr <<
      "\nView private key : " << viewSecretKeyStr << '\n';
    Common::Console::setTextColor(Common::Console::Color::Default);

    log(Logging::INFO) << "Saving wallet ...";

    std::fstream walletFile;
    createWalletFile(walletFile, config.walletFile);

    bool saveDetailed = false;
    bool saveCache = false;
    walletPtr->save(walletFile, saveDetailed, saveCache);
    walletFile.flush();

    log(Logging::INFO) << "Wallet is saved";
    log(Logging::INFO) << "Walletd is now closing ...";
  }
  else if (!config.walletSpendPrivateKey.empty() && !config.walletViewPrivateKey.empty())
  {
    // Restore wallet from private keys

    // check if spend private key is valid
    Crypto::Hash spendPrivateKeyHash;
    size_t spendPrivateKeyHashSize;

    if (!Common::fromHex(config.walletSpendPrivateKey, &spendPrivateKeyHash, sizeof(spendPrivateKeyHash), spendPrivateKeyHashSize) ||
      spendPrivateKeyHashSize != sizeof(spendPrivateKeyHash))
    {
      log(Logging::ERROR, Logging::BRIGHT_RED) << "Invalid spend private key";
      return;
    }

    // check if view private key is valid
    Crypto::Hash viewPrivateKeyHash;
    size_t viewPrivateKeyHashSize;

    if (!Common::fromHex(config.walletViewPrivateKey, &viewPrivateKeyHash, sizeof(viewPrivateKeyHash), viewPrivateKeyHashSize) ||
      viewPrivateKeyHashSize != sizeof(viewPrivateKeyHash))
    {
      log(Logging::ERROR, Logging::BRIGHT_RED) << "Invalid view private key";
      return;
    }

    // convert spend private key and view private key from Crypto::Hash to Crypto::SecretKey
    Crypto::SecretKey spendPrivateKey = *(struct Crypto::SecretKey *) &spendPrivateKeyHash;
    Crypto::SecretKey viewPrivateKey = *(struct Crypto::SecretKey *) &viewPrivateKeyHash;

    log(Logging::INFO) << "Restoring wallet from the given spend private key and view private key ...";

    CryptoNote::INode* nodeStub = NodeFactory::createNodeStub();
    std::unique_ptr<CryptoNote::INode> nodeGuard(nodeStub);

    CryptoNote::IWallet* walletPtr = new CryptoNote::WalletGreen(dispatcher, currency, *nodeStub);
    std::unique_ptr<CryptoNote::IWallet> walletGuard(walletPtr);
    walletPtr->initializeWithViewKey(viewPrivateKey, config.walletPassword);
    std::string address = walletPtr->createAddress(spendPrivateKey);

    log(Logging::INFO) << "Wallet was successfully restored";

    std::string spendSecretKeyStr = config.walletSpendPrivateKey;
    std::string viewSecretKeyStr = config.walletViewPrivateKey;

    Common::Console::setTextColor(Common::Console::Color::BrightCyan);
    std::cout <<
      "Address : " << address <<
      "\nSpend private key : " << spendSecretKeyStr <<
      "\nView private key : " << viewSecretKeyStr << '\n';
    Common::Console::setTextColor(Common::Console::Color::Default);

    log(Logging::INFO) << "Saving wallet ...";

    std::fstream walletFile;
    createWalletFile(walletFile, config.walletFile);

    bool saveDetailed = false;
    bool saveCache = false;
    walletPtr->save(walletFile, saveDetailed, saveCache);
    walletFile.flush();

    log(Logging::INFO) << "Wallet is saved";
    log(Logging::INFO) << "Walletd is now closing ...";
  }
  else
  {
    // missing the spend private key or the view private key
    log(Logging::ERROR, Logging::BRIGHT_RED) << "Must specify both spend private key and view private key to restore wallet";
  }
}

namespace {

bool checkPaymentId(const std::string& paymentIdStr)
{
  if (paymentIdStr.size() != 64)
  {
    return false;
  }

  return std::all_of(paymentIdStr.begin(), paymentIdStr.end(), [] (const char c) {
    if (c >= '0' && c <= '9') {
      return true;
    }

    if (c >= 'a' && c <= 'f') {
      return true;
    }

    if (c >= 'A' && c <= 'F') {
      return true;
    }

    return false;
  });
}

}

struct WalletHelper::TransactionsInBlockInfoFilter
{
  TransactionsInBlockInfoFilter(const std::vector<std::string>& addressesVec, const std::string& paymentIdStr) {
    addresses.insert(addressesVec.begin(), addressesVec.end());

    if (!paymentIdStr.empty()) {

      if (!checkPaymentId(paymentIdStr)) {
        throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
      }

      if (!Common::podFromHex(paymentIdStr, paymentId)) {
        throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
      }

      havePaymentId = true;
    } else {
      havePaymentId = false;
    }
  }

  bool checkTransaction(const CryptoNote::WalletTransactionWithTransfers& transaction) const {
    if (havePaymentId) {
      Crypto::Hash transactionPaymentId;
      if (!CryptoNote::getPaymentIdFromTxExtra(Common::asBinaryArray(transaction.transaction.extra), transactionPaymentId)) {
        return false;
      }

      if (paymentId != transactionPaymentId) {
        return false;
      }
    }

    if (addresses.empty()) {
      return true;
    }

    bool haveAddress = false;
    for (const CryptoNote::WalletTransfer& transfer: transaction.transfers) {
      if (addresses.find(transfer.address) != addresses.end()) {
        haveAddress = true;
        break;
      }
    }

    return haveAddress;
  }

  std::unordered_set<std::string> addresses;
  bool havePaymentId = false;
  Crypto::Hash paymentId;
};


// Public functions


WalletHelper::WalletHelper(const CryptoNote::Currency& currency, System::Dispatcher& dispatcher, CryptoNote::INode& node, CryptoNote::IWallet& wallet, const WalletConfiguration& config, Logging::ILogger& logger) :
  m_dispatcher(dispatcher),
  m_config(config),
  m_currency(currency),
  m_initialized(false),
  m_logger(logger, "WalletHelper"),
  m_node(node),
  m_readyEvent(m_dispatcher),
  m_refreshContext(m_dispatcher),
  m_wallet(wallet)
{
  m_readyEvent.set();
}

WalletHelper::~WalletHelper()
{
  if (m_initialized)
  {
    m_wallet.stop();
    m_refreshContext.wait();
    m_wallet.shutdown();
  }
}

std::error_code WalletHelper::createAddress(std::string& address)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::DEBUGGING) << "Creating a new address ...";

    address = m_wallet.createAddress();

    // call saveWallet() here
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while creating a new address: " << error.what();
    return error.code();
  }

  m_logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletHelper::createAddress(const std::string& spendPrivateKeyStr, std::string& address)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::DEBUGGING) << "Creating a new address ...";

    Crypto::SecretKey spendPrivateKey;
    if (!Common::podFromHex(spendPrivateKeyStr, spendPrivateKey))
    {
      m_logger(Logging::WARNING) << "Spend private key has wrong format : " << spendPrivateKeyStr;

      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = m_wallet.createAddress(spendPrivateKey);

    // call saveWallet() here
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while creating a new address : " << error.what();

    return error.code();
  }

  m_logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletHelper::createDelayedTransaction(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, std::string& transactionHash)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    // validate source addresses
    validateAddresses(request.addresses);

    // validate destination addresses
    validateAddresses(collectDestinationAddresses(request.transfers));

    if (!request.change_address.empty())
    {
      std::vector<std::string> changeAddress = { request.change_address };
      validateAddresses(changeAddress);
    }

    CryptoNote::TransactionParameters sendParams;

    if (!request.payment_id.empty())
    {
      addPaymentIdToExtra(request.payment_id, sendParams.extra);
    }
    else
    {
      sendParams.extra = Common::asString(Common::fromHex(request.extra));
    }

    sendParams.sourceAddresses = request.addresses;
    sendParams.destinations = convertWalletRpcOrdersToWalletOrders(request.transfers);
    sendParams.fee = request.fee;
    sendParams.mixIn = request.anonymity;
    sendParams.unlockTimestamp = request.unlock_time;
    sendParams.changeDestination = request.change_address;

    size_t transactionId = m_wallet.makeTransaction(sendParams);

    transactionHash = Common::podToHex(m_wallet.getTransaction(transactionId).hash);

    m_logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHash << " has been created";
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while creating delayed transaction : " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while creating delayed transaction : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::createTrackingAddress(const std::string& spendPublicKeyStr, std::string& address)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::DEBUGGING) << "Creating tracking address ...";

    Crypto::PublicKey spendPublicKey;
    if (!Common::podFromHex(spendPublicKeyStr, spendPublicKey))
    {
      m_logger(Logging::WARNING) << "Spend public key has wrong format : " << spendPublicKeyStr;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = m_wallet.createAddress(spendPublicKey);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while creating tracking address : " << error.what();
    return error.code();
  }

  m_logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletHelper::deleteAddress(const std::string& address)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::DEBUGGING) << "Delete address requested";
    m_wallet.deleteAddress(address);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while deleting address : " << error.what();
    return error.code();
  }

  m_logger(Logging::DEBUGGING) << "Address " << address << " was successfully deleted";

  return std::error_code();
}

std::error_code WalletHelper::deleteDelayedTransaction(const std::string& transactionHashStr)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    // validate transaction hash string
    Crypto::Hash transactionHashIgnore;
    if (!Common::podFromHex(transactionHashStr, transactionHashIgnore)) {
      m_logger(Logging::WARNING) << "Transaction hash string validation failed " << transactionHashStr;
      throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_HASH_FORMAT));
    }

    auto it = m_transactionHashStrIndexMap.find(transactionHashStr);
    
    if (it == m_transactionHashStrIndexMap.end())
    {
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    }

    size_t transactionId = it->second;
    m_wallet.rollbackUncommitedTransaction(transactionId);

    m_logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHashStr << " has been canceled";

  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while deleting delayed transaction : " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while deleting delayed transaction : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getAddresses(std::vector<std::string>& addresses)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    addresses.clear();

    size_t walletAddressCount = m_wallet.getAddressCount();

    addresses.reserve(walletAddressCount);

    for (size_t i = 0; i < walletAddressCount; ++i)
    {
      addresses.push_back(m_wallet.getAddress(i));
    }
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Can't get wallet addresses : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getAddressesCount(size_t& addressesCount)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    addressesCount = m_wallet.getAddressCount();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Can't get wallet addresses count : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedBalance)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::DEBUGGING) << "Getting balance for address " << address;

    availableBalance = m_wallet.getActualBalance(address);

    lockedBalance = m_wallet.getPendingBalance(address);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting balance for address " << address << " : " << error.what();
    return error.code();
  }

  m_logger(Logging::DEBUGGING) << address << "Actual balance : " << availableBalance << ", pending : " << lockedBalance;
  return std::error_code();
}

std::error_code WalletHelper::getBalance(uint64_t& availableBalance, uint64_t& lockedBalance)
{
  try
  {
    System::EventLock lock(m_readyEvent);
  
    m_logger(Logging::DEBUGGING) << "Getting wallet balance";

    availableBalance = m_wallet.getActualBalance();
    
    lockedBalance = m_wallet.getPendingBalance();
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting balance : " << error.what();
    return error.code();
  }

  m_logger(Logging::DEBUGGING) << "Wallet actual balance : " << availableBalance << ", pending : " << lockedBalance;
  return std::error_code();
}

std::error_code WalletHelper::getBlockHashes(uint32_t firstBlockIndex, uint32_t blockCount, std::vector<std::string>& blockHashStrings)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    std::vector<Crypto::Hash> blockHashes = m_wallet.getBlockHashes(firstBlockIndex, blockCount);

    blockHashStrings.reserve(blockHashes.size());
    for (const Crypto::Hash& blockHash: blockHashes)
    {
      blockHashStrings.push_back(Common::podToHex(blockHash));
    }
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting block hashes: " << error.what();
    return error.code();
  }

  return std::error_code();
}

std::error_code WalletHelper::getDelayedTransactionHashes(std::vector<std::string>& transactionHashStrings)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    std::vector<size_t> transactionIndexes = m_wallet.getDelayedTransactionIds();
    transactionHashStrings.reserve(transactionIndexes.size());

    for (size_t transactionIndex : transactionIndexes)
    {
      transactionHashStrings.emplace_back(Common::podToHex(m_wallet.getTransaction(transactionIndex).hash));
    }

  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting delayed transaction hashes: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting delayed transaction hashes: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getSpendPrivateKey(const std::string& address, std::string& spendPrivateKeyStr)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    CryptoNote::KeyPair spendKeyPair = m_wallet.getAddressSpendKey(address);

    spendPrivateKeyStr = Common::podToHex(spendKeyPair.secretKey);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting spend private key for address " << address << " : " << error.what();
    return error.code();
  }

  return std::error_code();
}

std::error_code WalletHelper::getSpendPrivateKeys(std::vector<std::string>& spendPrivateKeyStrings)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    size_t walletAddressCount = m_wallet.getAddressCount();

    for (size_t i = 0; i < walletAddressCount; ++i)
    {
      CryptoNote::KeyPair spendKeyPair = m_wallet.getAddressSpendKey(i);
      spendPrivateKeyStrings.emplace_back(Common::podToHex(spendKeyPair.secretKey));
    }

  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting spend private keys : " << error.what();
    return error.code();
  }

  return std::error_code();
}

std::error_code WalletHelper::getStatus(uint32_t& blockCount, uint32_t& knownBlockCount, std::string& lastBlockHash, uint32_t& peerCount, uint64_t& minimalFee)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    knownBlockCount = m_node.getKnownBlockCount();
    peerCount = m_node.getPeerCount();
    blockCount = m_wallet.getBlockCount();
    minimalFee = m_node.getMinimalFee();

    std::vector<Crypto::Hash> blockHashes = m_wallet.getBlockHashes(blockCount - 1, 1);
    lastBlockHash = Common::podToHex(blockHashes.back());
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting status: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting status: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getTransaction(const std::string& transactionHashStr, TransactionRpcInfo& transactionRpcInfo)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    Crypto::Hash transactionHash = hashStringToHash(transactionHashStr);

    CryptoNote::WalletTransactionWithTransfers transactionWithTransfers = m_wallet.getTransaction(transactionHash);

    if (transactionWithTransfers.transaction.state == CryptoNote::WalletTransactionState::DELETED)
    {
      m_logger(Logging::WARNING) << "Transaction " << transactionHashStr << " is deleted";
      return make_error_code(CryptoNote::error::OBJECT_NOT_FOUND);
    }

    transactionRpcInfo = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting transaction: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting transaction: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getTransactionHashes(const std::vector<std::string>& addresses, const std::string& blockHashStr, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(addresses);

    if (!paymentId.empty())
    {
      validatePaymentId(paymentId);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    Crypto::Hash blockHash = hashStringToHash(blockHashStr);

    transactionHashes = getRpcTransactionHashes(blockHash, blockCount, transactionFilter);
  }
  catch (std::system_error& x)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << x.what();
    return x.code();
  }
  catch (std::exception& x)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getTransactionHashes(const std::vector<std::string>& addresses, uint32_t firstBlockIndex, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(addresses);

    if (!paymentId.empty())
    {
      validatePaymentId(paymentId);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    transactionHashes = getRpcTransactionHashes(firstBlockIndex, blockCount, transactionFilter);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getTransactions(const std::vector<std::string>& addresses, const std::string& blockHashString, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(addresses);

    if (!paymentId.empty())
    {
      validatePaymentId(paymentId);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);

    Crypto::Hash blockHash = hashStringToHash(blockHashString);

    transactions = getRpcTransactions(blockHash, blockCount, transactionFilter);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getTransactions(const std::vector<std::string>& addresses, uint32_t firstBlockIndex, uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(addresses);

    if (!paymentId.empty())
    {
      validatePaymentId(paymentId);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);

    transactions = getRpcTransactions(firstBlockIndex, blockCount, transactionFilter);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting transactions: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getUnconfirmedTransactionHashes(const std::vector<std::string>& addresses, std::vector<std::string>& transactionHashes)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(addresses);

    std::vector<CryptoNote::WalletTransactionWithTransfers> transactions = m_wallet.getUnconfirmedTransactions();

    TransactionsInBlockInfoFilter transactionFilter(addresses, "");

    for (const CryptoNote::WalletTransactionWithTransfers& transaction: transactions)
    {
      if (transactionFilter.checkTransaction(transaction))
      {
        transactionHashes.emplace_back(Common::podToHex(transaction.transaction.hash));
      }
    }
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting unconfirmed transaction hashes: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while getting unconfirmed transaction hashes: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::getViewPrivateKey(std::string& viewPrivateKey)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    CryptoNote::KeyPair viewKeyPair = m_wallet.getViewKey();
    viewPrivateKey = Common::podToHex(viewKeyPair.secretKey);
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while getting view key: " << error.what();
    return error.code();
  }

  return std::error_code();
}

void WalletHelper::init()
{
  loadWallet();
  loadTransactionIdIndex();

  m_refreshContext.spawn([this] { refresh(); });

  m_initialized = true;
}

std::error_code WalletHelper::replaceWithNewWallet(const std::string& viewPrivateKeyStr)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    Crypto::SecretKey viewPrivateKey;
    if (!Common::podFromHex(viewPrivateKeyStr, viewPrivateKey))
    {
      m_logger(Logging::WARNING) << "View private key has invalid format " << viewPrivateKeyStr;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    Crypto::PublicKey viewPublicKeyIgnore;
    if (!Crypto::secret_key_to_public_key(viewPrivateKey, viewPublicKeyIgnore))
    {
      m_logger(Logging::WARNING) << "Cannot derive view public key, wrong view private key " << viewPrivateKeyStr;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    m_wallet.stop();
    m_wallet.shutdown();
    m_initialized = false;
    m_refreshContext.wait();

    m_transactionHashStrIndexMap.clear();

    m_wallet.start();
    m_wallet.initializeWithViewKey(viewPrivateKey, m_config.walletPassword);
    m_initialized = true;

    m_logger(Logging::INFO) << "The container has been replaced";
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while replacing container: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while replacing container: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::resetWallet()
{
  try
  {
    System::EventLock lock(m_readyEvent);

    m_logger(Logging::INFO) << "Reseting wallet ...";

    if (!m_initialized)
    {
      m_logger(Logging::WARNING) << "WALLETD_RPC_COMMAND_RESET impossible : Walletd is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    secureSaveWallet(m_wallet, m_config.walletFile, false, false);
    m_wallet.stop();
    m_wallet.shutdown();
    m_initialized = false;
    m_refreshContext.wait();

    m_wallet.start();
    init();

    m_logger(Logging::INFO) << "Wallet has been reset";
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while reseting wallet : " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while reseting wallet : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

void WalletHelper::saveWallet()
{
  secureSaveWallet(m_wallet, m_config.walletFile, true, true);
  m_logger(Logging::INFO) << "Wallet is saved";
}

std::error_code WalletHelper::sendDelayedTransaction(const std::string& transactionHashStr)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    hashStringToHash(transactionHashStr); // validate transactionHashStr parameter

    auto it = m_transactionHashStrIndexMap.find(transactionHashStr);
    if (it == m_transactionHashStrIndexMap.end())
    {
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    }

    size_t transactionIndex = it->second;

    m_wallet.commitTransaction(transactionIndex);

    m_logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHashStr << " has been sent";
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while sending delayed transaction hashes: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while sending delayed transaction hashes: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::sendTransaction(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, std::string& transactionHash, std::string& transactionPrivateKeyStr)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    validateAddresses(request.source_addresses);
    validateAddresses(collectDestinationAddresses(request.transfers));

    if (!request.change_address.empty())
    {
      std::vector<std::string> changeAddress = { request.change_address };
      validateAddresses(changeAddress);
    }

    if (request.anonymity > m_currency.maxMixin())
    {
      m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Mixin must be less than " << m_currency.maxMixin() + 1;
      throw std::system_error(make_error_code(CryptoNote::error::MIXIN_COUNT_TOO_BIG));
    }

    CryptoNote::TransactionParameters sendParams;
    if (!request.payment_id.empty())
    {
      addPaymentIdToExtra(request.payment_id, sendParams.extra);
    }
    else
    {
      sendParams.extra = Common::asString(Common::fromHex(request.extra));
    }

    sendParams.sourceAddresses = request.source_addresses;
    sendParams.destinations = convertWalletRpcOrdersToWalletOrders(request.transfers);
    sendParams.fee = request.fee;
    sendParams.mixIn = request.anonymity;
    sendParams.unlockTimestamp = request.unlock_time;
    sendParams.changeDestination = request.change_address;

    Crypto::SecretKey transactionPrivateKey;                      
    size_t transactionIndex = m_wallet.transfer(sendParams, transactionPrivateKey);
    transactionHash = Common::podToHex(m_wallet.getTransaction(transactionIndex).hash);
    transactionPrivateKeyStr = Common::podToHex(transactionPrivateKey);                                             

    m_logger(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been sent";
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING) << "Error while sending transaction: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while sending transaction: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletHelper::validateAddress(const std::string& address, bool& addressValid)
{
  try
  {
    System::EventLock lock(m_readyEvent);

    CryptoNote::AccountPublicAddress account = boost::value_initialized<CryptoNote::AccountPublicAddress>();
    if (m_currency.parseAccountAddressString(address, account))
    {
      addressValid = true;
    }
    else
    {
      addressValid = false;
    }
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while validating address: " << error.what();
    return error.code();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while validating address: " << e.what();
    return make_error_code(CryptoNote::error::BAD_ADDRESS);
  }

  return std::error_code();
}


// Private functions


void WalletHelper::addPaymentIdToExtra(const std::string& paymentId, std::string& extra)
{
  std::vector<uint8_t> extraVector;
  
  if (!CryptoNote::createTxExtraWithPaymentId(paymentId, extraVector))
  {
    throw std::runtime_error("Couldn't add payment id to extra");
  }

  std::copy(extraVector.begin(), extraVector.end(), std::back_inserter(extra));
}

std::vector<std::string> WalletHelper::collectDestinationAddresses(const std::vector<WalletRpcOrder>& orders)
{
  std::vector<std::string> addresses;

  addresses.reserve(orders.size());
  
  for (const WalletRpcOrder& order: orders)
  {
    addresses.push_back(order.address);
  }

  return addresses;
}

std::vector<TransactionHashesInBlockRpcInfo> WalletHelper::convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) const {

  std::vector<TransactionHashesInBlockRpcInfo> transactionHashes;
  transactionHashes.reserve(blocks.size());
  for (const CryptoNote::TransactionsInBlockInfo& block: blocks) {
    TransactionHashesInBlockRpcInfo item;
    item.block_hash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transaction: block.transactions) {
      item.transaction_hashes.emplace_back(Common::podToHex(transaction.transaction.hash));
    }

    transactionHashes.push_back(std::move(item));
  }

  return transactionHashes;
}

std::vector<TransactionsInBlockRpcInfo> WalletHelper::convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) const {

  std::vector<TransactionsInBlockRpcInfo> rpcBlocks;
  rpcBlocks.reserve(blocks.size());
  for (const auto& block: blocks) {
    TransactionsInBlockRpcInfo rpcBlock;
    rpcBlock.block_hash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers: block.transactions) {
      TransactionRpcInfo transactionInfo = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
      rpcBlock.transactions.push_back(std::move(transactionInfo));
    }

    rpcBlocks.push_back(std::move(rpcBlock));
  }

  return rpcBlocks;
}

TransactionRpcInfo WalletHelper::convertTransactionWithTransfersToTransactionRpcInfo(const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers) const
{

  TransactionRpcInfo transactionRpcInfo;

  transactionRpcInfo.state = static_cast<uint8_t>(transactionWithTransfers.transaction.state);
  transactionRpcInfo.transaction_hash = Common::podToHex(transactionWithTransfers.transaction.hash);
  transactionRpcInfo.block_index = transactionWithTransfers.transaction.blockHeight;
  transactionRpcInfo.timestamp = transactionWithTransfers.transaction.timestamp;
  transactionRpcInfo.is_base = transactionWithTransfers.transaction.isBase;
  transactionRpcInfo.unlock_time = transactionWithTransfers.transaction.unlockTime;
  transactionRpcInfo.amount = transactionWithTransfers.transaction.totalAmount;
  transactionRpcInfo.fee = transactionWithTransfers.transaction.fee;
  transactionRpcInfo.extra = Common::toHex(transactionWithTransfers.transaction.extra.data(), transactionWithTransfers.transaction.extra.size());
  transactionRpcInfo.payment_id = getPaymentIdStringFromExtra(transactionWithTransfers.transaction.extra);

  for (const CryptoNote::WalletTransfer& transfer: transactionWithTransfers.transfers)
  {
    TransferRpcInfo rpcTransfer;
    rpcTransfer.address = transfer.address;
    rpcTransfer.amount = transfer.amount;
    rpcTransfer.type = static_cast<uint8_t>(transfer.type);

    transactionRpcInfo.transfers.push_back(std::move(rpcTransfer));
  }

  return transactionRpcInfo;
}

std::vector<CryptoNote::WalletOrder> WalletHelper::convertWalletRpcOrdersToWalletOrders(const std::vector<WalletRpcOrder>& walletRpcOrders)
{
  std::vector<CryptoNote::WalletOrder> result;
  result.reserve(walletRpcOrders.size());

  for (const WalletRpcOrder& walletRpcOrder: walletRpcOrders)
  {
    CryptoNote::WalletOrder walletOrder = {walletRpcOrder.address, walletRpcOrder.amount};
    result.emplace_back(walletOrder);
  }

  return result;
}

bool WalletHelper::createOutputBinaryFile(const std::string& filename, std::fstream& file)
{
  file.open(filename.c_str(), std::fstream::in | std::fstream::out | std::ofstream::binary);
  if (file) {
    file.close();
    return false;
  }

  file.open(filename.c_str(), std::fstream::out | std::fstream::binary);
  return true;
}

std::string WalletHelper::createTemporaryFile(const std::string& path, std::fstream& tempFile)
{
  bool created = false;
  std::string temporaryName;

  for (size_t i = 1; i < 100; i++)
  {
    temporaryName = path + "." + std::to_string(i++);

    if (createOutputBinaryFile(temporaryName, tempFile)) {
      created = true;
      break;
    }
  }

  if (!created) {
    throw std::runtime_error("Couldn't create temporary file : " + temporaryName);
  }

  return temporaryName;
}

std::vector<CryptoNote::TransactionsInBlockInfo> WalletHelper::filterTransactions(const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks, const TransactionsInBlockInfoFilter& filter) const
{
  std::vector<CryptoNote::TransactionsInBlockInfo> result;

  for (const CryptoNote::TransactionsInBlockInfo& block: blocks)
  {
    bool transactionFound = false;
    CryptoNote::TransactionsInBlockInfo item;
    item.blockHash = block.blockHash;

    for (const CryptoNote::WalletTransactionWithTransfers& transaction: block.transactions)
    {
      if (transaction.transaction.state != CryptoNote::WalletTransactionState::DELETED && filter.checkTransaction(transaction))
      {
        item.transactions.push_back(transaction);

        if (transactionFound == false)
        {
          transactionFound = true;
        }
      }
    }

    if (transactionFound == true)
    {
      result.push_back(std::move(item));
    }
  }

  return result;
}

std::string WalletHelper::getPaymentIdStringFromExtra(const std::string& binaryString) const {
  Crypto::Hash paymentId;

  if (!CryptoNote::getPaymentIdFromTxExtra(Common::asBinaryArray(binaryString), paymentId)) {
    return std::string();
  }

  return Common::podToHex(paymentId);
}

std::vector<TransactionsInBlockRpcInfo> WalletHelper::getRpcTransactions(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const
{
  std::vector<CryptoNote::TransactionsInBlockInfo> transactions = m_wallet.getTransactions(blockHash, blockCount);

  if (transactions.empty())
  {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(transactions, filter);

  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionsInBlockRpcInfo> WalletHelper::getRpcTransactions(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const
{
  std::vector<CryptoNote::TransactionsInBlockInfo> transactions = m_wallet.getTransactions(firstBlockIndex, blockCount);

  if (transactions.empty())
  {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(transactions, filter);

  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionHashesInBlockRpcInfo> WalletHelper::getRpcTransactionHashes(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const
{
  std::vector<CryptoNote::TransactionsInBlockInfo> transactions = m_wallet.getTransactions(blockHash, blockCount);

  if (transactions.empty())
  {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(transactions, filter);

  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionHashesInBlockRpcInfo> WalletHelper::getRpcTransactionHashes(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const
{
  std::vector<CryptoNote::TransactionsInBlockInfo> transactions = m_wallet.getTransactions(firstBlockIndex, blockCount);

  if (transactions.empty())
  {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(transactions, filter);

  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

Crypto::Hash WalletHelper::hashStringToHash(const std::string& hashString)
{
  Crypto::Hash hash;

  if (!Common::podFromHex(hashString, hash)) {
    m_logger(Logging::WARNING) << "Can't parse hash string " << hashString;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_HASH_FORMAT));
  }

  return hash;
}

void WalletHelper::loadWallet()
{
  std::ifstream inputStream;

  inputStream.open(m_config.walletFile.c_str(), std::fstream::in | std::fstream::binary);

  if (!inputStream)
  {
    throw std::runtime_error("Couldn't open wallet file");
  }

  m_logger(Logging::INFO) << "Loading wallet ...";

  m_wallet.load(inputStream, m_config.walletPassword);

  m_logger(Logging::INFO) << "Wallet loading is finished.";
}

void WalletHelper::loadTransactionIdIndex()
{
  m_transactionHashStrIndexMap.clear();

  size_t walletTransactionCount = m_wallet.getTransactionCount();

  for (size_t i = 0; i < walletTransactionCount; ++i)
  {
    m_transactionHashStrIndexMap.emplace(Common::podToHex(m_wallet.getTransaction(i).hash), i);
  }
}

void WalletHelper::refresh()
{
  try
  {
    m_logger(Logging::DEBUGGING) << "Refresh is started";
    
    for (;;)
    {
      auto event = m_wallet.getEvent();
      if (event.type == CryptoNote::TRANSACTION_CREATED)
      {
        size_t transactionIndex = event.transactionCreated.transactionIndex;
        m_transactionHashStrIndexMap.emplace(Common::podToHex(m_wallet.getTransaction(transactionIndex).hash), transactionIndex);
      }
    }
  }
  catch (std::system_error& error)
  {
    m_logger(Logging::DEBUGGING) << "refresh is stopped: " << error.what();
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "exception thrown in refresh(): " << e.what();
  }
}

void WalletHelper::secureSaveWallet(CryptoNote::IWallet& wallet, const std::string& path, bool saveDetailed, bool saveCache)
{
  std::fstream tempFile;
  std::string tempFilePath = createTemporaryFile(path, tempFile);

  try
  {
    wallet.save(tempFile, saveDetailed, saveCache);
    tempFile.flush();
  }
  catch (std::exception& )
  {
    // delete temporary wallet file
    boost::system::error_code deleteErrorIgnore;
    boost::filesystem::remove(tempFilePath, deleteErrorIgnore);

    tempFile.close();
    throw;
  }

  tempFile.close();

  // replace wallet files
  Tools::replace_file(tempFilePath, path);
}

void WalletHelper::validateAddresses(const std::vector<std::string>& addresses)
{
  for (const std::string& address: addresses)
  {
    if (!CryptoNote::validateAddress(address, m_currency))
    {
      m_logger(Logging::WARNING) << "Address validation failed for " << address;
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
  }
}

void WalletHelper::validatePaymentId(const std::string& paymentId)
{
  if (!checkPaymentId(paymentId))
  {
    m_logger(Logging::WARNING) << "Can't validate payment id: " << paymentId;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }
}

} // end namespace PaymentService
