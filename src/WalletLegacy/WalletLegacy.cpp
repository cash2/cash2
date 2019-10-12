// Copyright (c) 2011-2016 The Cryptonote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>
#include <time.h>

#include "WalletLegacy.h"
#include "WalletLegacy/WalletHelper.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include "WalletLegacy/WalletUtils.h"

namespace CryptoNote {

namespace {

const uint64_t ACCOUNT_CREATE_TIME_ACCURACY = 24 * 60 * 60;

class WalletAsyncContextCounterDecrementer
{
public:
  WalletAsyncContextCounterDecrementer(WalletAsyncContextCounter& walletAsyncContextCounter) :
    m_walletAsyncContextCounter(walletAsyncContextCounter) {}
  ~WalletAsyncContextCounterDecrementer() { m_walletAsyncContextCounter.decrementAsyncContextCounter(); }

private:
  WalletAsyncContextCounter& m_walletAsyncContextCounter;
};

template <typename F>
void runAtomic(std::mutex& mutex, F f) {
  std::unique_lock<std::mutex> lock(mutex);
  f();
}

class InitWaiter : public IWalletLegacyObserver {
public:
  InitWaiter() : future(promise.get_future()) {}

  virtual void initCompleted(std::error_code result) override {
    promise.set_value(result);
  }

  std::error_code waitInit() {
    return future.get();
  }
private:
  std::promise<std::error_code> promise;
  std::future<std::error_code> future;
};

class SaveWaiter : public IWalletLegacyObserver {
public:
  SaveWaiter() : future(promise.get_future()) {}

  virtual void saveCompleted(std::error_code result) override {
    promise.set_value(result);
  }

  std::error_code waitSave() {
    return future.get();
  }

private:
  std::promise<std::error_code> promise;
  std::future<std::error_code> future;
};

} // end anonymous namespace


// Public functions


WalletLegacy::WalletLegacy(const Currency& currency, INode& node) :
  m_walletState(NOT_INITIALIZED),
  m_currency(currency),
  m_node(node),
  m_walletTransactionSenderIsStopping(false),
  m_lastNotifiedActualBalance(0),
  m_lastNotifiedPendingBalance(0),
  m_blockchainSynchronizer(node, currency.genesisBlockHash()),
  m_transfersSynchronizer(currency, m_blockchainSynchronizer, node),
  m_transfersContainerPtr(nullptr),
  m_walletLegacyCache(m_currency.mempoolTxLiveTime()),
  m_walletTransactionSenderPtr(nullptr),
  m_syncStarterPtr(new SyncStarter(m_blockchainSynchronizer))
{
  addObserver(m_syncStarterPtr.get());
}

WalletLegacy::~WalletLegacy()
{
  removeObserver(m_syncStarterPtr.get());

  {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_walletState != NOT_INITIALIZED) {
      m_walletTransactionSenderPtr->stop();
      m_walletTransactionSenderIsStopping = true;
    }
  }

  m_blockchainSynchronizer.removeObserver(this);
  m_blockchainSynchronizer.stop();
  m_walletAsyncContextCounter.waitAsyncContextsFinish();
  m_walletTransactionSenderPtr.release();
}

uint64_t WalletLegacy::actualBalance()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_transfersContainerPtr->balance(ITransfersContainer::IncludeKeyUnlocked) -
    m_walletLegacyCache.unconfrimedOutsAmount();
}

void WalletLegacy::addObserver(IWalletLegacyObserver* observer)
{
  m_observerManager.add(observer);
}

std::error_code WalletLegacy::cancelTransaction(size_t transactionIndex)
{
  return make_error_code(error::TX_CANCEL_IMPOSSIBLE);
}

std::error_code WalletLegacy::changePassword(const std::string& oldPassword, const std::string& newPassword)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  if (m_password.compare(oldPassword) != 0)
  {
    return make_error_code(error::WRONG_PASSWORD);
  }

  m_password = newPassword;

  return std::error_code();
}

void WalletLegacy::getAccountKeys(AccountKeys& keys)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  keys = m_account.getAccountKeys();
}

std::string WalletLegacy::getAddress()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_currency.accountAddressAsString(m_account);
}

bool WalletLegacy::getTransaction(size_t transactionIndex, WalletLegacyTransaction& transaction)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_walletLegacyCache.getTransaction(transactionIndex, transaction);
}

size_t WalletLegacy::getTransactionCount()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_walletLegacyCache.getTransactionCount();
}

size_t WalletLegacy::getTransactionIndex(size_t transferIndex)
{
  std::unique_lock<std::mutex> lock(m_mutex);
  
  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_walletLegacyCache.getTransactionIndex(transferIndex);
}

Crypto::SecretKey WalletLegacy::getTransactionPrivateKey(const Crypto::Hash& transactionHash)
{
  size_t transactionIndex = m_walletLegacyCache.getTransactionIndex(transactionHash);
  WalletLegacyTransaction transaction;
  getTransaction(transactionIndex, transaction);

  if (transaction.secretKey)
  {
     return reinterpret_cast<const Crypto::SecretKey&>(transaction.secretKey.get());
  }

  return NULL_SECRET_KEY;
}

bool WalletLegacy::getTransfer(size_t transferIndex, WalletLegacyTransfer& transfer)
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_walletLegacyCache.getTransfer(transferIndex, transfer);
}

size_t WalletLegacy::getTransferCount()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  return m_walletLegacyCache.getTransferCount();
}

void WalletLegacy::initAndGenerate(const std::string& password) // SimpleWallet create new wallet
{
  {
    std::unique_lock<std::mutex> stateLock(m_mutex);

    if (m_walletState != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.generate();
    m_password = password;

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::initAndLoad(std::istream& inputStream, const std::string& password) // SimpleWallet open existing wallet
{
  std::unique_lock<std::mutex> stateLock(m_mutex);

  if (m_walletState != NOT_INITIALIZED) {
    throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
  }

  m_password = password;
  m_walletState = LOADING;
      
  m_walletAsyncContextCounter.incrementAsyncContextCounter();
  std::thread loader(&WalletLegacy::load, this, std::ref(inputStream));
  loader.detach();
}

void WalletLegacy::initWithKeys(const AccountKeys& accountKeys, const std::string& password) // SimpleWallet restore wallet from private keys
{
  {
    std::unique_lock<std::mutex> stateLock(m_mutex);

    if (m_walletState != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.setAccountKeys(accountKeys);
    m_account.set_createtime(ACCOUNT_CREATE_TIME_ACCURACY);
    m_password = password;

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

uint64_t WalletLegacy::pendingBalance()
{
  std::unique_lock<std::mutex> lock(m_mutex);

  if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
    throw std::system_error(make_error_code(error::NOT_INITIALIZED));
  }

  assert(m_transfersContainerPtr);

  uint64_t change = m_walletLegacyCache.unconfrimedOutsAmount() - m_walletLegacyCache.unconfirmedTransactionsAmount();
  return m_transfersContainerPtr->balance(ITransfersContainer::IncludeKeyNotUnlocked) + change;
}

void WalletLegacy::removeObserver(IWalletLegacyObserver* observer)
{
  m_observerManager.remove(observer);
}

void WalletLegacy::reset()
{
  try {
    std::error_code saveError;
    std::stringstream ss;
    {
      SaveWaiter saveWaiter;
      WalletHelper::WalletLegacySmartObserver saveGuarantee(*this, saveWaiter);
      save(ss, false, false);
      saveError = saveWaiter.waitSave();
    }

    if (!saveError) {
      shutdown();
      InitWaiter initWaiter;
      WalletHelper::WalletLegacySmartObserver initGuarantee(*this, initWaiter);
      initAndLoad(ss, m_password);
      initWaiter.waitInit();
    }
  } catch (std::exception& e) {
    std::cout << "exception in reset: " << e.what() << std::endl;
  }
}

void WalletLegacy::save(std::ostream& destination, bool saveDetailed, bool saveCache)
{
  if(m_walletTransactionSenderIsStopping) {
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, make_error_code(error::OPERATION_CANCELLED));
    return;
  }

  {
    std::unique_lock<std::mutex> lock(m_mutex);

    throwIf(m_walletState != INITIALIZED, error::WRONG_STATE);

    m_walletState = SAVING;
  }

  m_walletAsyncContextCounter.incrementAsyncContextCounter();
  std::thread saver(&WalletLegacy::doSave, this, std::ref(destination), saveDetailed, saveCache);
  saver.detach();
}

size_t WalletLegacy::sendTransaction(const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp)
{
  std::vector<WalletLegacyTransfer> transfers;
  transfers.push_back(transfer);

  {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
      throw std::system_error(make_error_code(error::NOT_INITIALIZED));
    }
  }

  assert(m_transfersContainerPtr);

  return sendTransaction(transfers, fee, extra, mixIn, unlockTimestamp);
}

size_t WalletLegacy::sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp)
{
  size_t transactionIndex = 0;
  std::shared_ptr<WalletRequest> sendRequest;
  std::deque<std::shared_ptr<WalletLegacyEvent>> events;

  {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_walletState == NOT_INITIALIZED || m_walletState == LOADING) {
      throw std::system_error(make_error_code(error::NOT_INITIALIZED));
    }

    assert(m_transfersContainerPtr);

    sendRequest = m_walletTransactionSenderPtr->makeSendRequest(transactionIndex, events, transfers, fee, extra, mixIn, unlockTimestamp);
  }

  notifyClients(events);

  if (sendRequest) {
    m_walletAsyncContextCounter.incrementAsyncContextCounter();
    sendRequest->perform(m_node, std::bind(&WalletLegacy::sendTransactionCallback, this, std::placeholders::_1, std::placeholders::_2));
  }

  return transactionIndex;
}

void WalletLegacy::shutdown() {
  {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_walletTransactionSenderIsStopping)
    {
      throw std::runtime_error("The behavior is not defined!");
    }

    m_walletTransactionSenderIsStopping = true;

    if (m_walletState != INITIALIZED)
    {
      throw std::runtime_error("The behavior is not defined!");
    }

    m_walletTransactionSenderPtr->stop();
  }

  m_blockchainSynchronizer.removeObserver(this);
  m_blockchainSynchronizer.stop();
  m_walletAsyncContextCounter.waitAsyncContextsFinish();

  m_walletTransactionSenderPtr.release();
   
  {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_walletTransactionSenderIsStopping = false;
    m_walletState = NOT_INITIALIZED;

    const AccountPublicAddress& accountAddress = m_account.getAccountKeys().address;
    ITransfersSubscription* subscriptionPtr = m_transfersSynchronizer.getSubscription(accountAddress);
    assert(subscriptionPtr != nullptr);
    subscriptionPtr->removeObserver(this);
    m_transfersSynchronizer.removeSubscription(accountAddress);
    m_transfersContainerPtr = nullptr;

    m_walletLegacyCache.reset();
    m_lastNotifiedActualBalance = 0;
    m_lastNotifiedPendingBalance = 0;
  }
}


// Private functions


std::vector<size_t> WalletLegacy::deleteOutdatedUnconfirmedTransactions()
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_walletLegacyCache.deleteOutdatedTransactions();
}

void WalletLegacy::doSave(std::ostream& destination, bool saveDetailed, bool saveTransfersSynchronizerCache)
{
  WalletAsyncContextCounterDecrementer walletAsyncContextCounterDecrementer(m_walletAsyncContextCounter);

  try {
    m_blockchainSynchronizer.stop();
    std::unique_lock<std::mutex> lock(m_mutex);
    
    WalletLegacySerializer walletLegacySerializer(m_account, m_walletLegacyCache);
    std::string transfersSynchronizerCache;

    if (saveTransfersSynchronizerCache) {
      std::stringstream stream;
      m_transfersSynchronizer.save(stream);
      transfersSynchronizerCache = stream.str();
    }

    walletLegacySerializer.serialize(destination, m_password, saveDetailed, transfersSynchronizerCache);

    m_walletState = INITIALIZED;
    m_blockchainSynchronizer.start(); //XXX: start can throw. what to do in this case?
  }
  catch (std::system_error& e) {
    runAtomic(m_mutex, [this] () {this->m_walletState = WalletLegacy::INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, e.code());
    return;
  }
  catch (std::exception&) {
    runAtomic(m_mutex, [this] () {this->m_walletState = WalletLegacy::INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, make_error_code(error::INTERNAL_WALLET_ERROR));
    return;
  }

  m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, std::error_code());
}

void WalletLegacy::initSync()
{
  AccountSubscription accountSubscription;
  accountSubscription.keys = reinterpret_cast<const AccountKeys&>(m_account.getAccountKeys());
  accountSubscription.transactionSpendableAge = 1;
  accountSubscription.syncStart.height = 0;
  accountSubscription.syncStart.timestamp = m_account.get_createtime() - ACCOUNT_CREATE_TIME_ACCURACY;
  
  ITransfersSubscription& subscription = m_transfersSynchronizer.addSubscription(accountSubscription);
  m_transfersContainerPtr = &subscription.getContainer();
  subscription.addObserver(this);

  m_walletTransactionSenderPtr.reset(new WalletTransactionSender(m_currency, m_walletLegacyCache, m_account.getAccountKeys(), *m_transfersContainerPtr));
  m_walletState = INITIALIZED;
  
  m_blockchainSynchronizer.addObserver(this);
}

void WalletLegacy::load(std::istream& inputStream)
{
  WalletAsyncContextCounterDecrementer walletAsyncContextCounterDecrementer(m_walletAsyncContextCounter);
  try {
    std::unique_lock<std::mutex> lock(m_mutex);
    
    std::string transfersSynchronizerCache;
    WalletLegacySerializer walletLegacySerializer(m_account, m_walletLegacyCache);
    walletLegacySerializer.deserialize(inputStream, m_password, transfersSynchronizerCache);
      
    initSync();

    if (!transfersSynchronizerCache.empty()) {
      std::stringstream stream(transfersSynchronizerCache);
      m_transfersSynchronizer.load(stream);
    }
    
    // This is for fixing the burning bug
    // Read all output keys in the cache
    std::vector<TransactionOutputInformation> allTransfers;
    m_transfersContainerPtr->getOutputs(allTransfers, ITransfersContainer::IncludeAll);
    for (const TransactionOutputInformation& transactionOutputInformation : allTransfers) {
      if (transactionOutputInformation.type != TransactionTypes::OutputType::Invalid) {
        m_transfersSynchronizer.addPublicKeysSeen(m_account.getAccountKeys().address, transactionOutputInformation.transactionHash, transactionOutputInformation.outputKey);
      }
    }

  } catch (std::system_error& e) {
    runAtomic(m_mutex, [this] () {this->m_walletState = WalletLegacy::NOT_INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::initCompleted, e.code());
    return;
  } catch (std::exception&) {
    runAtomic(m_mutex, [this] () {this->m_walletState = WalletLegacy::NOT_INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::initCompleted, make_error_code(error::INTERNAL_WALLET_ERROR));
    return;
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::notifyClients(std::deque<std::shared_ptr<WalletLegacyEvent> >& events)
{
  while (!events.empty()) {
    std::shared_ptr<WalletLegacyEvent> event = events.front();
    event->notify(m_observerManager);
    events.pop_front();
  }
}

void WalletLegacy::notifyIfBalanceChanged()
{
  uint64_t actual_balance = actualBalance();
  uint64_t prev_actual_balance = m_lastNotifiedActualBalance.exchange(actual_balance);

  if (prev_actual_balance != actual_balance) {
    m_observerManager.notify(&IWalletLegacyObserver::actualBalanceUpdated, actual_balance);
  }

  uint64_t pending_balance = pendingBalance();
  uint64_t prev_pending_balance = m_lastNotifiedPendingBalance.exchange(pending_balance);

  if (prev_pending_balance != pending_balance) {
    m_observerManager.notify(&IWalletLegacyObserver::pendingBalanceUpdated, pending_balance);
  }

}

void WalletLegacy::onTransactionDeleted(ITransfersSubscription* object, const Crypto::Hash& transactionHash)
{
  std::shared_ptr<WalletLegacyEvent> event;

  {
    std::unique_lock<std::mutex> lock(m_mutex);
    event = m_walletLegacyCache.onTransactionDeleted(transactionHash);
  }

  if (event.get()) {
    event->notify(m_observerManager);
  }
}

void WalletLegacy::onTransactionUpdated(ITransfersSubscription* object, const Crypto::Hash& transactionHash)
{
  std::shared_ptr<WalletLegacyEvent> event;

  TransactionInformation txInfo;
  uint64_t amountIn;
  uint64_t amountOut;
  if (m_transfersContainerPtr->getTransactionInformation(transactionHash, txInfo, &amountIn, &amountOut)) {
    std::unique_lock<std::mutex> lock(m_mutex);
    event = m_walletLegacyCache.onTransactionUpdated(txInfo, static_cast<int64_t>(amountOut) - static_cast<int64_t>(amountIn));
  }

  if (event.get()) {
    event->notify(m_observerManager);
  }
}

void WalletLegacy::sendTransactionCallback(WalletRequest::Callback callback, std::error_code ec)
{
  WalletAsyncContextCounterDecrementer walletAsyncContextCounterDecrementer(m_walletAsyncContextCounter);
  std::deque<std::shared_ptr<WalletLegacyEvent> > events;

  boost::optional<std::shared_ptr<WalletRequest> > nextRequest;
  {
    std::unique_lock<std::mutex> lock(m_mutex);
    callback(events, nextRequest, ec);
  }

  notifyClients(events);

  if (nextRequest) {
    m_walletAsyncContextCounter.incrementAsyncContextCounter();
    (*nextRequest)->perform(m_node, std::bind(&WalletLegacy::synchronizationCallback, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void WalletLegacy::synchronizationCallback(WalletRequest::Callback callback, std::error_code ec)
{
  WalletAsyncContextCounterDecrementer walletAsyncContextCounterDecrementer(m_walletAsyncContextCounter);

  std::deque<std::shared_ptr<WalletLegacyEvent> > events;
  boost::optional<std::shared_ptr<WalletRequest> > nextRequest;
  {
    std::unique_lock<std::mutex> lock(m_mutex);
    callback(events, nextRequest, ec);
  }

  notifyClients(events);

  if (nextRequest) {
    m_walletAsyncContextCounter.incrementAsyncContextCounter();
    (*nextRequest)->perform(m_node, std::bind(&WalletLegacy::synchronizationCallback, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void WalletLegacy::synchronizationCompleted(std::error_code result)
{
  if (result != std::make_error_code(std::errc::interrupted)) {
    m_observerManager.notify(&IWalletLegacyObserver::synchronizationCompleted, result);
  }

  if (result) {
    return;
  }

  std::vector<size_t> deletedTransactions = deleteOutdatedUnconfirmedTransactions();
  std::for_each(deletedTransactions.begin(), deletedTransactions.end(), [&] (size_t transactionIndex) {
    m_observerManager.notify(&IWalletLegacyObserver::transactionUpdated, transactionIndex);
  });

  notifyIfBalanceChanged();
}

void WalletLegacy::synchronizationProgressUpdated(uint32_t current, uint32_t total)
{
  auto deletedTransactions = deleteOutdatedUnconfirmedTransactions();

  // forward notification
  m_observerManager.notify(&IWalletLegacyObserver::synchronizationProgressUpdated, current, total);

  for (auto transactionIndex: deletedTransactions) {
    m_observerManager.notify(&IWalletLegacyObserver::transactionUpdated, transactionIndex);
  }

  // check if balance has changed and notify client
  notifyIfBalanceChanged();
}

} // end namespace CryptoNote