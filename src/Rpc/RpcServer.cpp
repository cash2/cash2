// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RpcServer.h"

#include <future>
#include <unordered_map>

// CryptoNote
#include "Common/StringTools.h"
#include "Common/Math.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"

#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

using namespace Logging;
using namespace Crypto;
using namespace Common;

namespace CryptoNote {

namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.addHeader("Content-Type", "application/json");

    std::string corsDomain = obj->getCorsDomain();

    if (!corsDomain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", corsDomain);
    }

    response.setBody(storeToJson(res.data()));
    return result;
  };
}

}
  
std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {
  
  // binary handlers
  { "/get_blocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/query_blocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/query_blocks_lite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/get_random_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), false } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },

  // json handlers
  { "/get_circulating_supply", { jsonMethod<COMMAND_RPC_GET_CIRCULATING_SUPPLY>(&RpcServer::on_get_circulating_supply), true } },
  { "/get_connections", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::on_get_connections), true } },
  { "/get_connections_count", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS_COUNT>(&RpcServer::on_get_connections_count), true } },
  { "/get_difficulty", { jsonMethod<COMMAND_RPC_GET_DIFFICULTY>(&RpcServer::on_get_difficulty), true } },
  { "/get_grey_peerlist", { jsonMethod<COMMAND_RPC_GET_GREY_PEERLIST>(&RpcServer::on_get_grey_peerlist), true } },
  { "/get_grey_peerlist_size", { jsonMethod<COMMAND_RPC_GET_GREY_PEERLIST_SIZE>(&RpcServer::on_get_grey_peerlist_size), true } },
  { "/get_height", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/get_incoming_connections", { jsonMethod<COMMAND_RPC_GET_INCOMING_CONNECTIONS>(&RpcServer::on_get_incoming_connections), true } },
  { "/get_incoming_connections_count", { jsonMethod<COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT>(&RpcServer::on_get_incoming_connections_count), true } },
  { "/get_info", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/get_mempool_transactions_count", { jsonMethod<COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT>(&RpcServer::on_get_mempool_transactions_count), true } },
  { "/get_orphan_blocks_count", { jsonMethod<COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT>(&RpcServer::on_get_orphan_blocks_count), true } },
  { "/get_outgoing_connections", { jsonMethod<COMMAND_RPC_GET_OUTGOING_CONNECTIONS>(&RpcServer::on_get_outgoing_connections), true } },
  { "/get_outgoing_connections_count", { jsonMethod<COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT>(&RpcServer::on_get_outgoing_connections_count), true } },
  { "/get_total_transactions_count", { jsonMethod<COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT>(&RpcServer::on_get_total_transactions_count), false } },
  { "/get_transactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/get_transaction_fee", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_FEE>(&RpcServer::on_get_transaction_fee), false } },
  { "/get_white_peerlist_size", { jsonMethod<COMMAND_RPC_GET_WHITE_PEERLIST_SIZE>(&RpcServer::on_get_white_peerlist_size), true } },
  { "/get_white_peerlist", { jsonMethod<COMMAND_RPC_GET_WHITE_PEERLIST>(&RpcServer::on_get_white_peerlist), true } },
  { "/send_raw_transaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::on_send_raw_tx), false } },
  
  // disabled in restricted rpc mode
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), false } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), false } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, core& c, NodeServer& p2p, const ICryptoNoteProtocolQuery& protocolQuery) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(c), m_p2p(p2p), m_protocolQuery(protocolQuery) {
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  auto url = request.getUrl();

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    response.setStatus(HttpResponse::STATUS_404);
    return;
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");

  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
  }

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    logger(TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
      { "check_payment", { makeMemberMethod(&RpcServer::on_check_payment), false } },
      { "get_block", { makeMemberMethod(&RpcServer::on_get_block), false } },
      { "get_block_count", { makeMemberMethod(&RpcServer::on_get_block_count), true } },
      { "get_block_header_by_hash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), false } },
      { "get_block_header_by_height", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), false } },
      { "get_block_template", { makeMemberMethod(&RpcServer::on_get_block_template), false } },
      { "get_blocks", { makeMemberMethod(&RpcServer::on_get_blocks_json), false } },
      { "get_currency_id", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "get_last_block_header", { makeMemberMethod(&RpcServer::on_get_last_block_header), false } },
      { "get_mempool", { makeMemberMethod(&RpcServer::on_get_mempool), false } },
      { "get_transaction", { makeMemberMethod(&RpcServer::on_get_transaction), false } },
      { "on_get_block_hash", { makeMemberMethod(&RpcServer::on_get_block_hash), false } },
      { "submit_block", { makeMemberMethod(&RpcServer::on_submit_block), false } },
    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  logger(TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

bool RpcServer::restrictRPC(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
  return true;
}

bool RpcServer::enableCors(const std::string domain) {
  m_cors_domain = domain;
  return true;
}

std::string RpcServer::getCorsDomain() {
  return m_cors_domain;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = asString(toBinaryArray(completeBlock->getBlock()));

    res.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      res.blocks.back().txs.push_back(asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexes(req.transaction_id, outputIndexes)) {
    res.status = "Failed";
    return true;
  }

  res.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  res.status = CORE_RPC_STATUS_OK;
  logger(TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]";
  return true;
}

bool RpcServer::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  res.status = "Failed";
  if (!m_core.get_random_outs_for_amounts(req, res)) {
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;

  std::stringstream ss;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

  std::for_each(res.outs.begin(), res.outs.end(), [&](outs_for_amount& ofa)  {
    ss << "[" << ofa.amount << "]:";

    assert(ofa.outs.size() && "internal error: ofa.outs.size() is empty");

    std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
    {
      ss << oe.global_amount_index << " ";
    });
    ss << ENDL;
  });
  std::string s = ss.str();
  logger(TRACE) << "COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  rsp.is_tail_block_actual = m_core.getPoolChanges(req.tail_block_id, req.known_txs_ids, addedTransactions, rsp.deleted_txs_ids);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      rsp.status = "Internal error";
      break;;
    }

    rsp.added_txs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.is_tail_block_actual = m_core.getPoolChangesLite(req.tail_block_id, req.known_txs_ids, rsp.added_txs, rsp.deleted_txs_ids);

  return true;
}

//
// JSON handlers
//

bool RpcServer::on_get_circulating_supply(const COMMAND_RPC_GET_CIRCULATING_SUPPLY::request& req, COMMAND_RPC_GET_CIRCULATING_SUPPLY::response& res) {
  res.circulating_supply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res) {
  m_p2p.get_payload_object().get_all_connections_addresses(res.connections);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_connections_count(const COMMAND_RPC_GET_CONNECTIONS_COUNT::request& req, COMMAND_RPC_GET_CONNECTIONS_COUNT::response& res) {
  res.connections_count = m_p2p.get_connections_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_difficulty(const COMMAND_RPC_GET_DIFFICULTY::request& req, COMMAND_RPC_GET_DIFFICULTY::response& res) {
  res.difficulty = m_core.getNextBlockDifficulty();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_grey_peerlist(const COMMAND_RPC_GET_GREY_PEERLIST::request& req, COMMAND_RPC_GET_GREY_PEERLIST::response& res) {
  std::list<PeerlistEntry> greyPeerlist;
  std::list<PeerlistEntry> whitePeerlistIgnore;

  m_p2p.getPeerlistManager().get_peerlist_full(greyPeerlist, whitePeerlistIgnore);

  for (PeerlistEntry const& peer : greyPeerlist)
  {
    res.grey_peerlist.push_back(Common::ipAddressToString(peer.adr.ip));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_grey_peerlist_size(const COMMAND_RPC_GET_GREY_PEERLIST_SIZE::request& req, COMMAND_RPC_GET_GREY_PEERLIST_SIZE::response& res) {
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.get_current_blockchain_height();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_incoming_connections(const COMMAND_RPC_GET_INCOMING_CONNECTIONS::request& req, COMMAND_RPC_GET_INCOMING_CONNECTIONS::response& res) {
  m_p2p.get_payload_object().get_incoming_connections_addresses(res.incoming_connections);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_incoming_connections_count(const COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::request& req, COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT::response& res) {
  uint64_t totalConnections = m_p2p.get_connections_count();
  size_t outgoingConnectionsCount = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = totalConnections - outgoingConnectionsCount;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.get_current_blockchain_height();
  res.difficulty = m_core.getNextBlockDifficulty();
  res.total_transactions_count = m_core.get_blockchain_total_transactions() - res.height; //without coinbase
  res.mempool_transactions_count = m_core.get_pool_transactions_count();
  res.orphan_blocks_count = m_core.get_alternative_blocks_count();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.connections_count = total_conn;
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.circulating_supply = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  res.transaction_fee = m_core.getMinimalFee();

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_mempool_transactions_count(const COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::request& req, COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT::response& res) {
  res.mempool_transactions_count = m_core.get_pool_transactions_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_orphan_blocks_count(const COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::request& req, COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT::response& res) {
  res.orphan_blocks_count = m_core.get_alternative_blocks_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_outgoing_connections(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS::request& req, COMMAND_RPC_GET_OUTGOING_CONNECTIONS::response& res) {
  m_p2p.get_payload_object().get_outgoing_connections_addresses(res.outgoing_connections);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_outgoing_connections_count(const COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::request& req, COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT::response& res) {
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_total_transactions_count(const COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::request& req, COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT::response& res) {
  uint32_t numCoinbaseTransactions = m_core.get_current_blockchain_height();
  res.total_transactions_count = m_core.get_blockchain_total_transactions() - numCoinbaseTransactions;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transaction_fee(const COMMAND_RPC_GET_TRANSACTION_FEE::request& req, COMMAND_RPC_GET_TRANSACTION_FEE::response& res) {
  res.transaction_fee = m_core.getMinimalFee();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  std::vector<Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!fromHex(tx_hex_str, b))
    {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Hash))
    {
      res.status = "Failed, size of data mismatch";
    }
    vh.push_back(*reinterpret_cast<const Hash*>(b.data()));
  }
  std::list<Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.transactions_as_hex.push_back(toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_transactions.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_white_peerlist(const COMMAND_RPC_GET_WHITE_PEERLIST::request& req, COMMAND_RPC_GET_WHITE_PEERLIST::response& res) {
  std::list<PeerlistEntry> greyPeerlistIgnore;
  std::list<PeerlistEntry> whitePeerlist;

  m_p2p.getPeerlistManager().get_peerlist_full(greyPeerlistIgnore, whitePeerlist);

  for (PeerlistEntry const& peer : whitePeerlist)
  {
    res.white_peerlist.push_back(Common::ipAddressToString(peer.adr.ip));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_white_peerlist_size(const COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::request& req, COMMAND_RPC_GET_WHITE_PEERLIST_SIZE::response& res) {
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res) {
  BinaryArray tx_blob;
  if (!fromHex(req.tx_as_hex, tx_blob))
  {
    logger(INFO) << "[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(INFO) << "[on_send_raw_tx]: Failed to process tx";
    res.status = "Failed";
    return true;
  }

  if (tvc.m_verification_failed)
  {
    logger(INFO) << "[on_send_raw_tx]: tx verification failed";
    res.status = "Failed";
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(INFO) << "[on_send_raw_tx]: tx accepted, but not relayed";
    res.status = "Not relayed";
    return true;
  }


  NOTIFY_NEW_TRANSACTIONS::request r;
  r.txs.push_back(asString(tx_blob));
  m_core.get_protocol()->relay_transactions(r);
  //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Failed, restricted";
    return false;
  }

  AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(req.miner_address, adr)) {
    res.status = "Failed, wrong address";
    return true;
  }

  if (!m_core.get_miner().start(adr, static_cast<size_t>(req.threads_count))) {
    res.status = "Failed, mining not started";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Failed, restricted";
    return false;
  }

  if (!m_core.get_miner().stop()) {
    res.status = "Failed, mining not stopped";
    return true;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Failed, restricted";
    return false;
  }

  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------
bool RpcServer::on_get_block_count(const COMMAND_RPC_GET_BLOCK_COUNT::request& req, COMMAND_RPC_GET_BLOCK_COUNT::response& res) {
  res.count = m_core.get_current_blockchain_height();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_hash(const COMMAND_RPC_GET_BLOCK_HASH::request& req, COMMAND_RPC_GET_BLOCK_HASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height())
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_get_block_template(const COMMAND_RPC_GET_BLOCK_TEMPLATE::request& req, COMMAND_RPC_GET_BLOCK_TEMPLATE::response& res) {
  if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "Too big reserved size, maximum 60" };
  }

  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();

  if (!req.wallet_address.size() || !m_core.currency().parseAccountAddressString(req.wallet_address, acc)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address" };
  }

  Block b = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(req.reserve_size, 0);
  if (!m_core.get_block_template(b, acc, res.difficulty, res.height, blob_reserve)) {
    logger(ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(b);
  PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(b.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < req.reserve_size) {
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!res.reserved_offset) {
      logger(ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    res.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (res.reserved_offset + req.reserve_size > block_blob.size()) {
      logger(ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    res.reserved_offset = 0;
  }

  res.block_template_blob = toHex(block_blob);
  res.status = CORE_RPC_STATUS_OK;
  res.coinbase_transaction = toHex(toBinaryArray(b.baseTransaction));

  BinaryArray baseTransactionBA = toBinaryArray(b.baseTransaction);

  // res.tranasction_hashes is used for the sole purpose of calculating the merkle root and does not affect what transaction hashes are included in the block

  if (baseTransactionBA.size() > 120)
  {
    BinaryArray baseTransactionHeadBA(baseTransactionBA.begin(), baseTransactionBA.end() - 120);

    Hash baseTransactionHeadHash = getBinaryArrayHash(baseTransactionHeadBA);

    res.transaction_hashes.push_back(Common::podToHex(baseTransactionHeadHash));
  }

  for (Crypto::Hash h : b.transactionHashes)
  {
    res.transaction_hashes.push_back(Common::podToHex(h));
  }

  return true;
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Hash currencyId = m_core.currency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

bool RpcServer::on_submit_block(const COMMAND_RPC_SUBMIT_BLOCK::request& req, COMMAND_RPC_SUBMIT_BLOCK::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!fromHex(req[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint64_t blockIndex, const Hash& hash, block_header_response& response) {
  response.timestamp = blk.timestamp;
  response.prev_hash = Common::podToHex(blk.previousBlockHash);
  response.merkle_root = Common::podToHex(blk.merkleRoot);
  response.nonce = blk.nonce;
  response.orphan_status = orphan_status;
  response.height = blockIndex + 1;
  response.depth = m_core.get_current_blockchain_height() - blockIndex - 1;
  response.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), response.difficulty);
  response.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  uint32_t topBlockIndex;
  Hash topBlockHash;
  
  m_core.get_blockchain_top(topBlockIndex, topBlockHash);

  Block topBlock;
  if (!m_core.getBlockByHash(topBlockHash, topBlock)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }
  
  fill_block_header_response(topBlock, false, topBlockIndex, topBlockHash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
  Hash blockHash;

  if (!parse_hash256(req.hash, blockHash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (block.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint64_t blockIndex = boost::get<BaseInput>(block.baseTransaction.inputs.front()).blockIndex;
  fill_block_header_response(block, false, blockIndex, blockHash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {

  if (req.height == 0) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT,
      std::string("Height must be greater than 0") };
  }

  uint32_t currentBlockchainHeight = m_core.get_current_blockchain_height();
  if (req.height > currentBlockchainHeight) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("Height is too big : ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(currentBlockchainHeight) };
  }

  uint32_t blockIndex = req.height - 1;
  Hash blockHash = m_core.getBlockIdByHeight(blockIndex);
  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: Cannot get block at height : " + std::to_string(req.height) };
  }

  fill_block_header_response(block, false, blockIndex, blockHash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_json(const COMMAND_RPC_GET_BLOCKS_JSON::request& req, COMMAND_RPC_GET_BLOCKS_JSON::response& res) {
  if (req.height == 0) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT,
      std::string("Height must be greater than 0") };
  }

  uint32_t currentBlockchainHeight = m_core.get_current_blockchain_height();
  if (req.height > currentBlockchainHeight) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("Height is too big : ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(currentBlockchainHeight) };
  }

  uint32_t startBlockIndex = req.height - 1;
  uint32_t numBlocksToPrint = 30;
  uint32_t lastBlockIndex = 0;
  if (req.height > numBlocksToPrint)  {
    uint32_t lastBlockHeight = req.height - numBlocksToPrint;
    lastBlockIndex = lastBlockHeight - 1;
  }

  for (uint32_t i = startBlockIndex; i >= lastBlockIndex; i--) {
    Hash blockHash = m_core.getBlockIdByHeight(static_cast<uint32_t>(i));
    Block block;
    if (!m_core.getBlockByHash(blockHash, block)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: Cannot get block at height " + std::to_string(i + 1) };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blockBlobSize = getObjectBinarySize(block);
    size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
    difficulty_type difficulty;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), difficulty);

    block_short_response block_short;
    block_short.timestamp = block.timestamp;
    block_short.height = i + 1;
    block_short.hash = Common::podToHex(blockHash);
    block_short.size = blockBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.transaction_count = block.transactionHashes.size() + 1;
    block_short.difficulty = difficulty;

    res.blocks.push_back(block_short);

    if (i == 0)
    {
      break;
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}



bool RpcServer::on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res) {
  Hash blockHash;

  try {
    uint32_t tempBlockHeight = boost::lexical_cast<uint32_t>(req.hash);

    if (tempBlockHeight == 0) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_SMALL_HEIGHT,
        std::string("Height must be greater than 0") };
    }

    uint32_t tempBlockIndex = tempBlockHeight - 1;
    blockHash = m_core.getBlockIdByHeight(tempBlockIndex);
  } catch (boost::bad_lexical_cast &) {
    if (!parse_hash256(req.hash, blockHash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
  }

  Block block;
  if (!m_core.getBlockByHash(blockHash, block)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (block.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t blockIndex = boost::get<BaseInput>(block.baseTransaction.inputs.front()).blockIndex;
  uint32_t blockHeight = blockIndex + 1;
  res.block.height = blockHeight;

  Crypto::Hash tempBlockHash = m_core.getBlockIdByHeight(blockIndex);
  bool isOrphaned = blockHash != tempBlockHash;
  res.block.is_orphaned = isOrphaned;

  block_header_response block_header;
  fill_block_header_response(block, isOrphaned, blockIndex, blockHash, block_header);

  res.block.timestamp = block_header.timestamp;
  res.block.prev_hash = block_header.prev_hash;
  res.block.merkle_root = block_header.merkle_root;
  res.block.nonce = block_header.nonce;
  res.block.hash = block_header.hash;
  res.block.depth = block_header.depth;
  m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), res.block.difficulty);

  res.block.total_reward = block_header.reward;

  size_t blockSize = 0;
  if (!m_core.getBlockSize(blockHash, blockSize)) {
    return false;
  }
  res.block.transactions_size = blockSize;

  size_t blokBlobSize = getObjectBinarySize(block);
  size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
  res.block.size = blokBlobSize + res.block.transactions_size - minerTxBlobSize;

  uint64_t alreadyGeneratedCoins;
  if (!m_core.getAlreadyGeneratedCoins(blockHash, alreadyGeneratedCoins)) {
    return false;
  }
  res.block.already_generated_coins = std::to_string(alreadyGeneratedCoins);

  if (!m_core.getGeneratedTransactionsNumber(blockIndex, res.block.already_generated_transactions)) {
    return false;
  }

  uint64_t prevBlockGeneratedCoins = 0;
  if (blockIndex > 0) {
    if (!m_core.getAlreadyGeneratedCoins(block.previousBlockHash, prevBlockGeneratedCoins)) {
      return false;
    }
  }

  uint64_t baseReward = 0;
  int64_t emissionChangeIgnore = 0;

  // removed hard fork 1 if clause here

  if (!m_core.getBlockReward2(blockHeight, res.block.transactions_size, prevBlockGeneratedCoins, 0, baseReward, emissionChangeIgnore)) {
    return false;
  }

  res.block.base_reward = baseReward;

  // Base transaction adding
  transaction_short_response transaction_short;
  transaction_short.hash = Common::podToHex(getObjectHash(block.baseTransaction));
  transaction_short.fee = 0;
  transaction_short.amount_out = get_outs_money_amount(block.baseTransaction);
  transaction_short.size = getObjectBinarySize(block.baseTransaction);
  res.block.transactions.push_back(transaction_short);


  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(block.transactionHashes, txs, missed_txs);

  res.block.total_fees = 0;

  for (const Transaction& tx : txs) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.block.transactions.push_back(transaction_short);

    res.block.total_fees += transaction_short.fee;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transaction(const COMMAND_RPC_GET_TRANSACTION::request& req, COMMAND_RPC_GET_TRANSACTION::response& res) {
  Hash transactionHash;

  if (!parse_hash256(req.hash, transactionHash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
  }

  std::vector<Crypto::Hash> transactionHashes;
  transactionHashes.push_back(transactionHash);

  std::list<Crypto::Hash> missedTransactionsIgnore;
  std::list<Transaction> transactions;
  m_core.getTransactions(transactionHashes, transactions, missedTransactionsIgnore, true);

  if (1 == transactions.size()) {
    res.transaction = transactions.front();
  } else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Transaction ID was not found"};
  }

  Crypto::Hash blockHash;
  uint32_t blockIndex;
  if (m_core.getBlockContainingTx(transactionHash, blockHash, blockIndex)) {
    Block block;
    if (m_core.getBlockByHash(blockHash, block)) {
      size_t totalBlockTransactionsSize;
      m_core.getBlockSize(blockHash, totalBlockTransactionsSize);
      size_t blockBlobSize = getObjectBinarySize(block);
      size_t minerTxBlobSize = getObjectBinarySize(block.baseTransaction);
      block_short_response block_short;

      block_short.timestamp = block.timestamp;
      block_short.height = blockIndex + 1;
      block_short.hash = Common::podToHex(blockHash);
      block_short.size = blockBlobSize + totalBlockTransactionsSize - minerTxBlobSize;
      block_short.transaction_count = block.transactionHashes.size() + 1;

      difficulty_type difficulty;
      m_core.getBlockDifficulty(static_cast<uint32_t>(blockIndex), difficulty);
      block_short.difficulty = difficulty;

      res.block = block_short;
    }
  }

  uint64_t amount_in = 0;
  get_inputs_money_amount(res.transaction, amount_in);
  uint64_t amount_out = get_outs_money_amount(res.transaction);

  res.transaction_details.hash = Common::podToHex(getObjectHash(res.transaction));
  res.transaction_details.fee = amount_in - amount_out;
  if (amount_in == 0)
  {
    res.transaction_details.fee = 0;
  }
  res.transaction_details.amount_out = amount_out;
  res.transaction_details.size = getObjectBinarySize(res.transaction);

  uint64_t ringSignatureSize;
  if (!getRingSignatureSize(res.transaction, ringSignatureSize)) {
    return false;
  }
  res.transaction_details.mixin = ringSignatureSize - 1;

  Crypto::Hash paymentId;
  if (CryptoNote::getPaymentIdFromTxExtra(res.transaction.extra, paymentId)) {
    res.transaction_details.payment_id = Common::podToHex(paymentId);
  } else {
    res.transaction_details.payment_id = "";
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::getRingSignatureSize(const Transaction& transaction, uint64_t& ringSignatureSize) {
  // base input
  if (transaction.inputs.size() == 1 && transaction.inputs[0].type() == typeid(BaseInput))
  {
    ringSignatureSize = 1;
    return true;
  }

  ringSignatureSize = 0;

  // key input
  for (const TransactionInput& txin : transaction.inputs) {
    if (txin.type() != typeid(KeyInput)) {
      continue;
    }
    uint64_t curRingSignatureSize = boost::get<KeyInput>(txin).outputIndexes.size();
    if (curRingSignatureSize > ringSignatureSize) {
      ringSignatureSize = curRingSignatureSize;
    }
  }

  return true;
}

bool RpcServer::on_get_mempool(const COMMAND_RPC_GET_MEMPOOL::request& req, COMMAND_RPC_GET_MEMPOOL::response& res) {
  auto pool = m_core.getMemoryPool();
  for (const CryptoNote::tx_memory_pool::TransactionDetails txd : pool) {
    mempool_transaction_response mempool_transaction;
    uint64_t amount_out = getOutputAmount(txd.tx);

    mempool_transaction.hash = Common::podToHex(txd.id);
    mempool_transaction.fee = txd.fee;
    mempool_transaction.amount_out = amount_out;
    mempool_transaction.size = txd.blobSize;
    mempool_transaction.receive_time = txd.receiveTime;
    res.mempool.push_back(mempool_transaction);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_payment(const COMMAND_RPC_CHECK_PAYMENT::request& req, COMMAND_RPC_CHECK_PAYMENT::response& res) {
	// parse txid
	Crypto::Hash txid;
	if (!parse_hash256(req.transaction_id, txid)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction id" };
	}
	// parse address
	CryptoNote::AccountPublicAddress address;
	if (!m_core.currency().parseAccountAddressString(req.receiver_address, address)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Receiver's address not found" };
	}
	// parse txkey
	Crypto::Hash tx_key_hash;
	size_t size;
	if (!Common::fromHex(req.transaction_private_key, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction secret key" };
	}
	Crypto::SecretKey tx_key = *(struct Crypto::SecretKey *) &tx_key_hash;

	// fetch tx
	Transaction tx;
	std::vector<Crypto::Hash> tx_ids;
	tx_ids.push_back(txid);
	std::list<Crypto::Hash> missed_txs;
	std::list<Transaction> txs;
	m_core.getTransactions(tx_ids, txs, missed_txs, true);

	if (1 == txs.size()) {
		tx = txs.front();
	}
	else {
		throw JsonRpc::JsonRpcError{
			CORE_RPC_ERROR_CODE_WRONG_PARAM,
			"Transaction ID was not found" };
	}
	CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

	// obtain key derivation
	Crypto::KeyDerivation derivation;
	if (!Crypto::generate_key_derivation(address.viewPublicKey, tx_key, derivation))
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
	}
	
	// look for outputs
	uint64_t received(0);
	size_t keyIndex(0);
	std::vector<TransactionOutput> outputs;
	try {
		for (const TransactionOutput& o : transaction.outputs) {
			if (o.target.type() == typeid(KeyOutput)) {
				const KeyOutput out_key = boost::get<KeyOutput>(o.target);
				Crypto::PublicKey pubkey;
				derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
				if (pubkey == out_key.key) {
					received += o.amount;
					outputs.push_back(o);
				}
			}
			++keyIndex;
		}
	}
	catch (...)
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
	}
	res.amount = received;
	res.outputs = outputs;
	res.status = CORE_RPC_STATUS_OK;
	return true;
}

} // end namespace CryptoNote
