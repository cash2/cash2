// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "WalletService.h"

namespace PaymentService {

class WalletdRpcCommands {

public :

  WalletdRpcCommands(WalletService& walletService);

  std::error_code handleCreateAddress(const WALLETD_RPC_COMMAND_CREATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_CREATE_ADDRESS::Response& response);
  std::error_code handleCreateDelayedTransaction(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Response& response);
  std::error_code handleDeleteAddress(const WALLETD_RPC_COMMAND_DELETE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_DELETE_ADDRESS::Response& response);
  std::error_code handleDeleteDelayedTransaction(const WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Response& response);
  std::error_code handleGetAddresses(const WALLETD_RPC_COMMAND_GET_ADDRESSES::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES::Response& response);
  std::error_code handleGetAddressesCount(const WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Response& response);
  std::error_code handleGetBalance(const WALLETD_RPC_COMMAND_GET_BALANCE::Request& request, WALLETD_RPC_COMMAND_GET_BALANCE::Response& response);
  std::error_code handleGetBlockHashes(const WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Response& response);
  std::error_code handleGetDelayedTransactionHashes(const WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Response& response);
  std::error_code handleGetSpendPrivateKey(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Response& response);
  std::error_code handleGetSpendPrivateKeys(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Response& response);
  std::error_code handleGetStatus(const WALLETD_RPC_COMMAND_GET_STATUS::Request& request, WALLETD_RPC_COMMAND_GET_STATUS::Response& response);
  std::error_code handleGetTransaction(const WALLETD_RPC_COMMAND_GET_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION::Response& response);
  std::error_code handleGetTransactionHashes(const WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Response& response);
  std::error_code handleGetTransactions(const WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Response& response);
  std::error_code handleGetUnconfirmedTransactionHashes(const WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Response& response);
  std::error_code handleGetViewKey(const WALLETD_RPC_COMMAND_GET_VIEW_KEY::Request& request, WALLETD_RPC_COMMAND_GET_VIEW_KEY::Response& response);
  std::error_code handleReset(const WALLETD_RPC_COMMAND_RESET::Request& request, WALLETD_RPC_COMMAND_RESET::Response& response);
  std::error_code handleSendDelayedTransaction(const WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Response& response);
  std::error_code handleSendTransaction(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_TRANSACTION::Response& response);
  std::error_code handleValidateAddress(const WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Response& response);

private :

  WalletService& service;

};

} // end namespace PaymentService