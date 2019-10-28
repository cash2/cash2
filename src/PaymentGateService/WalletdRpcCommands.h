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

  std::error_code handleCreateAddress(const CreateAddress::Request& request, CreateAddress::Response& response);
  std::error_code handleCreateDelayedTransaction(const CreateDelayedTransaction::Request& request, CreateDelayedTransaction::Response& response);
  std::error_code handleDeleteAddress(const DeleteAddress::Request& request, DeleteAddress::Response& response);
  std::error_code handleDeleteDelayedTransaction(const DeleteDelayedTransaction::Request& request, DeleteDelayedTransaction::Response& response);
  std::error_code handleGetAddresses(const GetAddresses::Request& request, GetAddresses::Response& response);
  std::error_code handleGetAddressesCount(const GetAddressesCount::Request& request, GetAddressesCount::Response& response);
  std::error_code handleGetBalance(const GetBalance::Request& request, GetBalance::Response& response);
  std::error_code handleGetBlockHashes(const GetBlockHashes::Request& request, GetBlockHashes::Response& response);
  std::error_code handleGetDelayedTransactionHashes(const GetDelayedTransactionHashes::Request& request, GetDelayedTransactionHashes::Response& response);
  std::error_code handleGetSpendPrivateKey(const GetSpendPrivateKey::Request& request, GetSpendPrivateKey::Response& response);
  std::error_code handleGetSpendPrivateKeys(const GetSpendPrivateKeys::Request& request, GetSpendPrivateKeys::Response& response);
  std::error_code handleGetStatus(const GetStatus::Request& request, GetStatus::Response& response);
  std::error_code handleGetTransaction(const GetTransaction::Request& request, GetTransaction::Response& response);
  std::error_code handleGetTransactionHashes(const GetTransactionHashes::Request& request, GetTransactionHashes::Response& response);
  std::error_code handleGetTransactions(const GetTransactions::Request& request, GetTransactions::Response& response);
  std::error_code handleGetUnconfirmedTransactionHashes(const GetUnconfirmedTransactionHashes::Request& request, GetUnconfirmedTransactionHashes::Response& response);
  std::error_code handleGetViewKey(const GetViewKey::Request& request, GetViewKey::Response& response);
  std::error_code handleReset(const Reset::Request& request, Reset::Response& response);
  std::error_code handleSendDelayedTransaction(const SendDelayedTransaction::Request& request, SendDelayedTransaction::Response& response);
  std::error_code handleSendTransaction(const SendTransaction::Request& request, SendTransaction::Response& response);
  std::error_code handleValidateAddress(const ValidateAddress::Request& request, ValidateAddress::Response& response);

private :

  WalletService& service;

};

} // end namespace PaymentService