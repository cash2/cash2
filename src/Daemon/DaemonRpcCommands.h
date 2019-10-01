// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "CryptoNoteCore/Core.h"
#include "P2p/NodeServer.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "Rpc/HttpServer.h"
#include "Logging/LoggerRef.h"
#include "Rpc/CoreRpcCommands.h"

namespace CryptoNote {

class DaemonRpcCommands {
public:
  DaemonRpcCommands(Logging::ILogger& log, Core& core, NodeServer& nodeServer, const ICryptoNoteProtocolQuery& cryptoNoteProtocolQuery);

  bool check_payment(const COMMAND_RPC_CHECK_PAYMENT::request& request, COMMAND_RPC_CHECK_PAYMENT::response& response);
  void fill_block_header_response(const Block& block, bool orphan_status, uint64_t blockIndex, const Crypto::Hash& blockHash, block_header_response& response);
  bool getRingSignatureSize(const Transaction& transaction, uint64_t& ringSignatureSize);
  bool get_block(const COMMAND_RPC_GET_BLOCK::request& request, COMMAND_RPC_GET_BLOCK::response& response);
  bool get_block_count(const COMMAND_RPC_GET_BLOCK_COUNT::request& request, COMMAND_RPC_GET_BLOCK_COUNT::response& response);
  bool get_block_hash(const COMMAND_RPC_GET_BLOCK_HASH::request& request, COMMAND_RPC_GET_BLOCK_HASH::response& response);
  bool get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& response);
  bool get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& response);
  bool get_block_template(const COMMAND_RPC_GET_BLOCK_TEMPLATE::request& request, COMMAND_RPC_GET_BLOCK_TEMPLATE::response& response);
  bool get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& request, COMMAND_RPC_GET_BLOCKS_FAST::response& response);
  bool get_blocks_json(const COMMAND_RPC_GET_BLOCKS_JSON::request& request, COMMAND_RPC_GET_BLOCKS_JSON::response& response);
  bool get_circulating_supply(const COMMAND_RPC_GET_CIRCULATING_SUPPLY::request& request, COMMAND_RPC_GET_CIRCULATING_SUPPLY::response& response);
  bool get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& request, COMMAND_RPC_GET_CONNECTIONS::response& response);
  bool get_connections_count(const COMMAND_RPC_GET_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_CONNECTIONS_COUNT::response& response);
  bool get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& request, COMMAND_RPC_GET_CURRENCY_ID::response& response);
  bool get_difficulty(const COMMAND_RPC_GET_DIFFICULTY::request& request, COMMAND_RPC_GET_DIFFICULTY::response& response);
  bool get_grey_peerlist(const COMMAND_RPC_GET_GREY_PEERLIST::request& request, COMMAND_RPC_GET_GREY_PEERLIST::response& response);
  bool get_grey_peerlist_size(const COMMAND_RPC_GET_GREY_PEERLIST_SIZE::request& request, COMMAND_RPC_GET_GREY_PEERLIST_SIZE::response& response);
  bool get_height(const COMMAND_RPC_GET_HEIGHT::request& request, COMMAND_RPC_GET_HEIGHT::response& response);
  bool get_incoming_connections(const COMMAND_RPC_GET_INCOMING_CONNECTIONS::request& request, COMMAND_RPC_GET_INCOMING_CONNECTIONS::response& response);
  bool get_incoming_connections_count(const COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::response& response);
  bool get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& request, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& response);
  bool get_info(const COMMAND_RPC_GET_INFO::request& request, COMMAND_RPC_GET_INFO::response& response);
  bool get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& request, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& response);
  bool get_mempool(const COMMAND_RPC_GET_MEMPOOL::request& request, COMMAND_RPC_GET_MEMPOOL::response& response);
  bool get_mempool_transactions_count(const COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::request& request, COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::response& response);
  bool get_orphan_blocks_count(const COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::request& request, COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::response& response);
  bool get_outgoing_connections(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS::request& request, COMMAND_RPC_GET_OUTGOING_CONNECTIONS::response& response);
  bool get_outgoing_connections_count(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::request& request, COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::response& response);
  bool get_pool_changes(const COMMAND_RPC_GET_POOL_CHANGES::request& request, COMMAND_RPC_GET_POOL_CHANGES::response& response);
  bool get_pool_changes_lite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& request, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& response);
  bool get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& request, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& response);
  bool get_total_transactions_count(const COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::request& request, COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::response& response);
  bool get_transaction(const COMMAND_RPC_GET_TRANSACTION::request& request, COMMAND_RPC_GET_TRANSACTION::response& response);
  bool get_transaction_fee(const COMMAND_RPC_GET_TRANSACTION_FEE::request& request, COMMAND_RPC_GET_TRANSACTION_FEE::response& response);
  bool get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& request, COMMAND_RPC_GET_TRANSACTIONS::response& response);
  bool get_white_peerlist(const COMMAND_RPC_GET_WHITE_PEERLIST::request& request, COMMAND_RPC_GET_WHITE_PEERLIST::response& response);
  bool get_white_peerlist_size(const COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::request& request, COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::response& response);
  bool query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& request, COMMAND_RPC_QUERY_BLOCKS::response& response);
  bool query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& request, COMMAND_RPC_QUERY_BLOCKS_LITE::response& response);
  bool send_raw_transaction(const COMMAND_RPC_SEND_RAW_TX::request& request, COMMAND_RPC_SEND_RAW_TX::response& response);
  bool start_mining(const COMMAND_RPC_START_MINING::request& request, COMMAND_RPC_START_MINING::response& response); // disabled in restricted rpc mode
  bool stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& request, COMMAND_RPC_STOP_DAEMON::response& response); // disabled in restricted rpc mode
  bool stop_mining(const COMMAND_RPC_STOP_MINING::request& request, COMMAND_RPC_STOP_MINING::response& response); // disabled in restricted rpc mode
  bool submit_block(const COMMAND_RPC_SUBMIT_BLOCK::request& request, COMMAND_RPC_SUBMIT_BLOCK::response& response);
  bool validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& request, COMMAND_RPC_VALIDATE_ADDRESS::response& response);

private :
  Logging::LoggerRef m_logger;
  Core& m_core;
  NodeServer& m_nodeServer;
  const ICryptoNoteProtocolQuery& m_cryptoNoteProtocolQuery;
};

} // end namespace CryptoNote
