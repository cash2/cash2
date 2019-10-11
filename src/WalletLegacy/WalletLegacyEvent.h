// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "IWalletLegacy.h"
#include "Common/ObserverManager.h"

namespace CryptoNote
{

class WalletLegacyEvent
{
public:
  virtual ~WalletLegacyEvent() {
  };

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) = 0;
};

class WalletTransactionUpdatedEvent : public WalletLegacyEvent
{
public:
  WalletTransactionUpdatedEvent(size_t transactionIndex) : m_transactionIndex(transactionIndex) {};
  virtual ~WalletTransactionUpdatedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::transactionUpdated, m_transactionIndex);
  }

private:
  size_t m_transactionIndex;
};

class WalletSendTransactionCompletedEvent : public WalletLegacyEvent
{
public:
  WalletSendTransactionCompletedEvent(size_t transactionIndex, std::error_code result) : m_transactionIndex(transactionIndex), m_error(result) {};
  virtual ~WalletSendTransactionCompletedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::sendTransactionCompleted, m_transactionIndex, m_error);
  }

private:
  size_t m_transactionIndex;
  std::error_code m_error;
};

class WalletExternalTransactionCreatedEvent : public WalletLegacyEvent
{
public:
  WalletExternalTransactionCreatedEvent(size_t transactionIndex) : m_transactionIndex(transactionIndex) {};
  virtual ~WalletExternalTransactionCreatedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::externalTransactionCreated, m_transactionIndex);
  }
private:
  size_t m_transactionIndex;
};

class WalletSynchronizationProgressUpdatedEvent : public WalletLegacyEvent
{
public:
  WalletSynchronizationProgressUpdatedEvent(uint32_t current, uint32_t total) : m_current(current), m_total(total) {};
  virtual ~WalletSynchronizationProgressUpdatedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::synchronizationProgressUpdated, m_current, m_total);
  }

private:
  uint32_t m_current;
  uint32_t m_total;
};

class WalletSynchronizationCompletedEvent : public WalletLegacyEvent {
public:
  WalletSynchronizationCompletedEvent(uint32_t current, uint32_t total, std::error_code result) : m_ec(result) {};
  virtual ~WalletSynchronizationCompletedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override {
    observer.notify(&IWalletLegacyObserver::synchronizationCompleted, m_ec);
  }

private:
  std::error_code m_ec;
};

class WalletActualBalanceUpdatedEvent : public WalletLegacyEvent
{
public:
  WalletActualBalanceUpdatedEvent(uint64_t balance) : m_balance(balance) {};
  virtual ~WalletActualBalanceUpdatedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::actualBalanceUpdated, m_balance);
  }
private:
  uint64_t m_balance;
};

class WalletPendingBalanceUpdatedEvent : public WalletLegacyEvent
{
public:
  WalletPendingBalanceUpdatedEvent(uint64_t balance) : m_balance(balance) {};
  virtual ~WalletPendingBalanceUpdatedEvent() {};

  virtual void notify(Tools::ObserverManager<IWalletLegacyObserver>& observer) override
  {
    observer.notify(&IWalletLegacyObserver::pendingBalanceUpdated, m_balance);
  }
private:
  uint64_t m_balance;
};

} /* namespace CryptoNote */
