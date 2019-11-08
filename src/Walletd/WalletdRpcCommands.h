// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "WalletHelper.h"

namespace Walletd {

class WalletdRpcCommands {

public :

  WalletdRpcCommands(WalletHelper& walletService);

  std::error_code createAddress(const WALLETD_RPC_COMMAND_CREATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_CREATE_ADDRESS::Response& response);
  std::error_code createAddresses(const WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Request& request, WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Response& response);
  std::error_code createDelayedTransaction(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Response& response);
  std::error_code deleteAddress(const WALLETD_RPC_COMMAND_DELETE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_DELETE_ADDRESS::Response& response);
  std::error_code deleteDelayedTransaction(const WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Response& response);
  std::error_code getAddresses(const WALLETD_RPC_COMMAND_GET_ADDRESSES::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES::Response& response);
  std::error_code getAddressesCount(const WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Response& response);
  std::error_code getBalance(const WALLETD_RPC_COMMAND_GET_BALANCE::Request& request, WALLETD_RPC_COMMAND_GET_BALANCE::Response& response);
  std::error_code getBlockHashes(const WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Response& response);
  std::error_code getDelayedTransactionHashes(const WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Response& response);
  std::error_code getSpendPrivateKey(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Response& response);
  std::error_code getSpendPrivateKeys(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Response& response);
  std::error_code getStatus(const WALLETD_RPC_COMMAND_GET_STATUS::Request& request, WALLETD_RPC_COMMAND_GET_STATUS::Response& response);
  std::error_code getTransaction(const WALLETD_RPC_COMMAND_GET_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION::Response& response);
  std::error_code getTransactionHashes(const WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Response& response);
  std::error_code getTransactions(const WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Response& response);
  std::error_code getUnconfirmedTransactionHashes(const WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Response& response);
  std::error_code getViewPrivateKey(const WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Request& request, WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Response& response);
  std::error_code reset(const WALLETD_RPC_COMMAND_RESET::Request& request, WALLETD_RPC_COMMAND_RESET::Response& response);
  std::error_code save(const WALLETD_RPC_COMMAND_SAVE::Request& request, WALLETD_RPC_COMMAND_SAVE::Response& response);
  std::error_code sendDelayedTransaction(const WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Response& response);
  std::error_code sendTransaction(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_TRANSACTION::Response& response);
  std::error_code validateAddress(const WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Response& response);

private :

  WalletHelper& m_walletHelper;

};

} // end namespace Walletd