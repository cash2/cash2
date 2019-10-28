// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletdRpcCommands.h"
#include "version.h"

namespace PaymentService {

WalletdRpcCommands::WalletdRpcCommands(WalletService& walletService) : service(walletService) {}

std::error_code WalletdRpcCommands::handleReset(const Reset::Request& request, Reset::Response& response) {
  if (request.view_private_key.empty()) {
    return service.resetWallet();
  } else {
    return service.replaceWithNewWallet(request.view_private_key);
  }
}

std::error_code WalletdRpcCommands::handleCreateAddress(const CreateAddress::Request& request, CreateAddress::Response& response) {
  if (request.spend_private_key.empty() && request.spend_public_key.empty()) {
    return service.createAddress(response.address);
  } else if (!request.spend_private_key.empty()) {
    return service.createAddress(request.spend_private_key, response.address);
  } else {
    return service.createTrackingAddress(request.spend_public_key, response.address);
  }
}

std::error_code WalletdRpcCommands::handleDeleteAddress(const DeleteAddress::Request& request, DeleteAddress::Response& response) {
  return service.deleteAddress(request.address);
}

std::error_code WalletdRpcCommands::handleGetSpendPrivateKey(const GetSpendPrivateKey::Request& request, GetSpendPrivateKey::Response& response) {
  return service.getSpendPrivateKey(request.address, response.spend_private_key);
}

std::error_code WalletdRpcCommands::handleGetSpendPrivateKeys(const GetSpendPrivateKeys::Request& request, GetSpendPrivateKeys::Response& response) {
  return service.getSpendPrivateKeys(response.spend_private_keys);
}

std::error_code WalletdRpcCommands::handleGetBalance(const GetBalance::Request& request, GetBalance::Response& response) {
  if (!request.address.empty()) {
    return service.getBalance(request.address, response.available_balance, response.locked_amount);
  } else {
    return service.getBalance(response.available_balance, response.locked_amount);
  }
}

std::error_code WalletdRpcCommands::handleGetBlockHashes(const GetBlockHashes::Request& request, GetBlockHashes::Response& response) {
  uint32_t startBlockIndex = request.start_block_height - 1;
  return service.getBlockHashes(startBlockIndex, request.number_of_blocks, response.block_hashes);
}

std::error_code WalletdRpcCommands::handleGetTransactionHashes(const GetTransactionHashes::Request& request, GetTransactionHashes::Response& response) {
  if (!request.start_block_hash.empty()) {
    return service.getTransactionHashes(request.addresses, request.start_block_hash, request.number_of_blocks, request.payment_id, response.items);
  } else {
    uint32_t startBlockIndex = request.start_block_height - 1;
    return service.getTransactionHashes(request.addresses, startBlockIndex, request.number_of_blocks, request.payment_id, response.items);
  }
}

std::error_code WalletdRpcCommands::handleGetTransactions(const GetTransactions::Request& request, GetTransactions::Response& response) {
  if (!request.start_block_hash.empty()) {
    return service.getTransactions(request.addresses, request.start_block_hash, request.number_of_blocks, request.payment_id, response.items);
  } else {
    uint32_t startBlockIndex = request.start_block_height - 1;
    return service.getTransactions(request.addresses, startBlockIndex, request.number_of_blocks, request.payment_id, response.items);
  }
}

std::error_code WalletdRpcCommands::handleGetUnconfirmedTransactionHashes(const GetUnconfirmedTransactionHashes::Request& request, GetUnconfirmedTransactionHashes::Response& response) {
  return service.getUnconfirmedTransactionHashes(request.addresses, response.transaction_hashes);
}

std::error_code WalletdRpcCommands::handleGetTransaction(const GetTransaction::Request& request, GetTransaction::Response& response) {
  return service.getTransaction(request.transaction_hash, response.transaction);
}

std::error_code WalletdRpcCommands::handleSendTransaction(const SendTransaction::Request& request, SendTransaction::Response& response) {
  return service.sendTransaction(request, response.transaction_hash, response.transaction_private_key);
}

std::error_code WalletdRpcCommands::handleCreateDelayedTransaction(const CreateDelayedTransaction::Request& request, CreateDelayedTransaction::Response& response) {
  return service.createDelayedTransaction(request, response.transaction_hash);
}

std::error_code WalletdRpcCommands::handleGetDelayedTransactionHashes(const GetDelayedTransactionHashes::Request& request, GetDelayedTransactionHashes::Response& response) {
  return service.getDelayedTransactionHashes(response.transaction_hashes);
}

std::error_code WalletdRpcCommands::handleDeleteDelayedTransaction(const DeleteDelayedTransaction::Request& request, DeleteDelayedTransaction::Response& response) {
  return service.deleteDelayedTransaction(request.transaction_hash);
}

std::error_code WalletdRpcCommands::handleSendDelayedTransaction(const SendDelayedTransaction::Request& request, SendDelayedTransaction::Response& response) {
  return service.sendDelayedTransaction(request.transaction_hash);
}

std::error_code WalletdRpcCommands::handleGetViewKey(const GetViewKey::Request& request, GetViewKey::Response& response) {
  return service.getViewKey(response.view_private_key);
}

std::error_code WalletdRpcCommands::handleGetStatus(const GetStatus::Request& request, GetStatus::Response& response) {
  response.cash2_software_version = PROJECT_VERSION_LONG;
  return service.getStatus(response.block_count, response.known_block_count, response.last_block_hash, response.peer_count, response.minimal_fee);
}

std::error_code WalletdRpcCommands::handleGetAddresses(const GetAddresses::Request& request, GetAddresses::Response& response) {
  return service.getAddresses(response.addresses);
}

std::error_code WalletdRpcCommands::handleGetAddressesCount(const GetAddressesCount::Request& request, GetAddressesCount::Response& response) {
  return service.getAddressesCount(response.addresses_count);
}

std::error_code WalletdRpcCommands::handleValidateAddress(const ValidateAddress::Request& request, ValidateAddress::Response& response) {
  return service.validateAddress(request.address, response.address_valid);
}

} // end namespace PaymentService