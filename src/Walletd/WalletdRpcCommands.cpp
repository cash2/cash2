// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletdRpcCommands.h"
#include "version.h"

namespace Walletd {

WalletdRpcCommands::WalletdRpcCommands(WalletHelper& walletHelper) : m_walletHelper(walletHelper) {}

std::error_code WalletdRpcCommands::createAddress(const WALLETD_RPC_COMMAND_CREATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_CREATE_ADDRESS::Response& response)
{
  if (request.spend_private_key.empty() && request.spend_public_key.empty())
  {
    return m_walletHelper.createAddress(response.address, response.spend_private_key);
  }
  else if (!request.spend_private_key.empty())
  {
    return m_walletHelper.createAddress(request.spend_private_key, response.address, response.spend_private_key);
  }
  else
  {
    return m_walletHelper.createTrackingAddress(request.spend_public_key, response.address);
  }
}

std::error_code WalletdRpcCommands::createAddresses(const WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Request& request, WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Response& response)
{
  return m_walletHelper.createAddresses(request.spend_private_keys, response.addresses);
}

std::error_code WalletdRpcCommands::createDelayedTransaction(const WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Response& response)
{
  return m_walletHelper.createDelayedTransaction(request, response.transaction_hash);
}

std::error_code WalletdRpcCommands::deleteAddress(const WALLETD_RPC_COMMAND_DELETE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_DELETE_ADDRESS::Response& response)
{
  return m_walletHelper.deleteAddress(request.address);
}

std::error_code WalletdRpcCommands::deleteDelayedTransaction(const WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Response& response)
{
  return m_walletHelper.deleteDelayedTransaction(request.transaction_hash);
}

std::error_code WalletdRpcCommands::getAddresses(const WALLETD_RPC_COMMAND_GET_ADDRESSES::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES::Response& response)
{
  return m_walletHelper.getAddresses(response.addresses);
}

std::error_code WalletdRpcCommands::getAddressesCount(const WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Request& request, WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Response& response)
{
  return m_walletHelper.getAddressesCount(response.addresses_count);
}

std::error_code WalletdRpcCommands::getBalance(const WALLETD_RPC_COMMAND_GET_BALANCE::Request& request, WALLETD_RPC_COMMAND_GET_BALANCE::Response& response)
{
  if (!request.address.empty())
  {
    return m_walletHelper.getBalance(request.address, response.available_balance, response.locked_amount);
  }
  else
  {
    return m_walletHelper.getBalance(response.available_balance, response.locked_amount);
  }
}

std::error_code WalletdRpcCommands::getBlockHashes(const WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Response& response)
{
  uint32_t startBlockIndex = request.start_block_height - 1;
  return m_walletHelper.getBlockHashes(startBlockIndex, request.number_of_blocks, response.block_hashes);
}

std::error_code WalletdRpcCommands::getDelayedTransactionHashes(const WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Response& response)
{
  return m_walletHelper.getDelayedTransactionHashes(response.transaction_hashes);
}

std::error_code WalletdRpcCommands::getSpendPrivateKey(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Response& response)
{
  return m_walletHelper.getSpendPrivateKey(request.address, response.spend_private_key);
}

std::error_code WalletdRpcCommands::getSpendPrivateKeys(const WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Request& request, WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Response& response)
{
  return m_walletHelper.getSpendPrivateKeys(response.spend_private_keys);
}

std::error_code WalletdRpcCommands::getStatus(const WALLETD_RPC_COMMAND_GET_STATUS::Request& request, WALLETD_RPC_COMMAND_GET_STATUS::Response& response)
{
  response.cash2_software_version = PROJECT_VERSION_LONG;

  return m_walletHelper.getStatus(response.block_count, response.known_block_count, response.last_block_hash, response.peer_count, response.minimal_fee);
}

std::error_code WalletdRpcCommands::getTransaction(const WALLETD_RPC_COMMAND_GET_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION::Response& response)
{
  return m_walletHelper.getTransaction(request.transaction_hash, response.transaction);
}

std::error_code WalletdRpcCommands::getTransactionHashes(const WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Response& response)
{
  if (!request.start_block_hash.empty())
  {
    return m_walletHelper.getTransactionHashes(request.addresses, request.start_block_hash, request.number_of_blocks, request.payment_id, response.items);
  }
  else
  {
    uint32_t startBlockIndex = request.start_block_height - 1;
    return m_walletHelper.getTransactionHashes(request.addresses, startBlockIndex, request.number_of_blocks, request.payment_id, response.items);
  }
}

std::error_code WalletdRpcCommands::getTransactions(const WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Request& request, WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Response& response)
{
  if (!request.start_block_hash.empty())
  {
    return m_walletHelper.getTransactions(request.addresses, request.start_block_hash, request.number_of_blocks, request.payment_id, response.items);
  }
  else
  {
    uint32_t startBlockIndex = request.start_block_height - 1;
    return m_walletHelper.getTransactions(request.addresses, startBlockIndex, request.number_of_blocks, request.payment_id, response.items);
  }
}

std::error_code WalletdRpcCommands::getUnconfirmedTransactionHashes(const WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Request& request, WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Response& response)
{
  return m_walletHelper.getUnconfirmedTransactionHashes(request.addresses, response.transaction_hashes);
}

std::error_code WalletdRpcCommands::getViewPrivateKey(const WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Request& request, WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Response& response)
{
  return m_walletHelper.getViewPrivateKey(response.view_private_key);
}

std::error_code WalletdRpcCommands::reset(const WALLETD_RPC_COMMAND_RESET::Request& request, WALLETD_RPC_COMMAND_RESET::Response& response)
{
  if (request.view_private_key.empty())
  {
    return m_walletHelper.resetWallet();
  }
  else
  {
    return m_walletHelper.replaceWithNewWallet(request.view_private_key);
  }
}

std::error_code WalletdRpcCommands::save(const WALLETD_RPC_COMMAND_SAVE::Request& request, WALLETD_RPC_COMMAND_SAVE::Response& response)
{
  return m_walletHelper.secureSaveWalletNoThrow();
}

std::error_code WalletdRpcCommands::sendDelayedTransaction(const WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Response& response)
{
  return m_walletHelper.sendDelayedTransaction(request.transaction_hash);
}

std::error_code WalletdRpcCommands::sendTransaction(const WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request& request, WALLETD_RPC_COMMAND_SEND_TRANSACTION::Response& response)
{
  return m_walletHelper.sendTransaction(request, response.transaction_hash, response.transaction_private_key);
}

std::error_code WalletdRpcCommands::validateAddress(const WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Request& request, WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Response& response)
{
  return m_walletHelper.validateAddress(request.address, response.address_valid);
}

} // end namespace Walletd