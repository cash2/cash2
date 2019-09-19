// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbowanec developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <future>
#include <boost/scope_exit.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "System/Dispatcher.h"
#include "CryptoNoteProtocolHandler.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/VerificationContext.h"
#include "P2p/LevinProtocol.h"

namespace CryptoNote {


// Public functions


CryptoNoteProtocolHandler::CryptoNoteProtocolHandler(const Currency& currency, System::Dispatcher& dispatcher, ICore& core, IP2pEndpoint* p2p, Logging::ILogger& log) :
  m_dispatcher(dispatcher),
  m_currency(currency),
  m_core(core),
  m_p2p(p2p),
  m_synchronized(false),
  m_stop(false),
  m_observedHeight(0),
  m_peerCount(0),
  m_logger(log, "protocol")
{
  if (!m_p2p)
  {
    m_p2p = &m_p2p_stub;
  }
}

bool CryptoNoteProtocolHandler::addObserver(ICryptoNoteProtocolObserver* observer)
{
  return m_observerManager.add(observer);
}

uint32_t CryptoNoteProtocolHandler::getObservedHeight() const
{
  std::lock_guard<std::mutex> lock(m_observedHeightMutex);
  return m_observedHeight;
};

size_t CryptoNoteProtocolHandler::getPeerCount() const
{
  return m_peerCount;
}

void CryptoNoteProtocolHandler::get_all_connections_addresses(std::vector<std::string>& addresses)
{
  m_p2p->for_each_connection([&](const CryptoNoteConnectionContext& context, PeerIdType peerIdIgnore) {
    addresses.push_back(Common::ipAddressToString(context.m_remote_ip) + ":" + std::to_string(context.m_remote_port));
  });
}

void CryptoNoteProtocolHandler::get_incoming_connections_addresses(std::vector<std::string>& addresses)
{
  m_p2p->for_each_connection([&](const CryptoNoteConnectionContext& context, PeerIdType peerIdIgnore) {
    if (context.m_is_income)
    {
      addresses.push_back(Common::ipAddressToString(context.m_remote_ip) + ":" + std::to_string(context.m_remote_port));
    }
  });
}

void CryptoNoteProtocolHandler::get_outgoing_connections_addresses(std::vector<std::string>& addresses)
{
  m_p2p->for_each_connection([&](const CryptoNoteConnectionContext& context, PeerIdType peerIdIgnore) {
    if (!context.m_is_income)
    {
      addresses.push_back(Common::ipAddressToString(context.m_remote_ip) + ":" + std::to_string(context.m_remote_port));
    }
  });
}

bool CryptoNoteProtocolHandler::get_payload_sync_data(CORE_SYNC_DATA& syncData)
{
  // gets information about our daemon
  uint32_t currentHeight;
  m_core.get_blockchain_top(currentHeight, syncData.top_id);
  syncData.current_height = currentHeight + 1;
  return true;
}

bool CryptoNoteProtocolHandler::get_stat_info(core_stat_info& info)
{
  return m_core.get_stat_info(info);
}

template <typename Command, typename Handler>
int notifyAdaptor(const BinaryArray& reqBuf, CryptoNoteConnectionContext& ctx, Handler handler)
{

  typedef typename Command::request Request;
  int command = Command::ID;

  Request req = boost::value_initialized<Request>();
  if (!LevinProtocol::decode(reqBuf, req)) {
    throw std::runtime_error("Failed to load_from_binary in command " + std::to_string(command));
  }

  return handler(command, req, ctx);
}

#define HANDLE_NOTIFY(CMD, Handler) case CMD::ID: { ret = notifyAdaptor<CMD>(in, ctx, std::bind(Handler, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)); break; }

int CryptoNoteProtocolHandler::handleCommand(bool is_notify, int command, const BinaryArray& in, BinaryArray& out, CryptoNoteConnectionContext& ctx, bool& handled)
{
  int ret = 0;
  handled = true;

  switch (command) {
    HANDLE_NOTIFY(NOTIFY_NEW_BLOCK, &CryptoNoteProtocolHandler::handle_notify_new_block)
    HANDLE_NOTIFY(NOTIFY_NEW_TRANSACTIONS, &CryptoNoteProtocolHandler::handle_notify_new_transactions)
    HANDLE_NOTIFY(NOTIFY_REQUEST_CHAIN, &CryptoNoteProtocolHandler::handle_request_chain)
    HANDLE_NOTIFY(NOTIFY_REQUEST_GET_OBJECTS, &CryptoNoteProtocolHandler::handle_request_get_objects)
    HANDLE_NOTIFY(NOTIFY_REQUEST_TX_POOL, &CryptoNoteProtocolHandler::handle_request_mempool)
    HANDLE_NOTIFY(NOTIFY_RESPONSE_CHAIN_ENTRY, &CryptoNoteProtocolHandler::handle_response_chain_entry)
    HANDLE_NOTIFY(NOTIFY_RESPONSE_GET_OBJECTS, &CryptoNoteProtocolHandler::handle_response_get_objects)

  default:
    handled = false;
  }

  return ret;
}

#undef HANDLE_NOTIFY

void CryptoNoteProtocolHandler::onConnectionClosed(const CryptoNoteConnectionContext& context)
{
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(m_observedHeightMutex);
    uint64_t prevHeight = m_observedHeight;
    recalculateMaxObservedHeight(context.m_connection_id);
    if (prevHeight != m_observedHeight) {
      updated = true;
    }
  }

  if (updated) {
    m_logger(Logging::TRACE) << "Observed height updated: " << m_observedHeight;
    m_observerManager.notify(&ICryptoNoteProtocolObserver::lastKnownBlockHeightUpdated, m_observedHeight);
  }

  if (context.m_state != CryptoNoteConnectionContext::state_before_handshake) {
    m_peerCount--;
    m_observerManager.notify(&ICryptoNoteProtocolObserver::peerCountUpdated, m_peerCount.load());
  }
}

void CryptoNoteProtocolHandler::onConnectionOpened(CryptoNoteConnectionContext& context)
{
}

bool CryptoNoteProtocolHandler::on_idle()
{
  return m_core.on_idle();
}

bool CryptoNoteProtocolHandler::process_payload_sync_data(const CORE_SYNC_DATA& syncData, CryptoNoteConnectionContext& context, bool is_initial)
{
  // Process the synchronization data a peer node sends to our node

  if (context.m_state == CryptoNoteConnectionContext::state_before_handshake && !is_initial)
  {
    return true;
  }

  if (context.m_state == CryptoNoteConnectionContext::state_synchronizing) {
  } else if (m_core.have_block(syncData.top_id)) {
    if (is_initial) {
      on_connection_synchronized();
      context.m_state = CryptoNoteConnectionContext::state_pool_sync_required;
    } else {
      context.m_state = CryptoNoteConnectionContext::state_normal;
    }
  } else {
    int64_t diff = static_cast<int64_t>(syncData.current_height) - static_cast<int64_t>(get_current_blockchain_height());

    m_logger(diff >= 0 ? (is_initial ? Logging::INFO : Logging::DEBUGGING) : Logging::TRACE, Logging::BRIGHT_YELLOW) << context <<
      "Sync data returned unknown top block: " << get_current_blockchain_height() << " -> " << syncData.current_height
      << " [" << std::abs(diff) << " blocks (" << std::abs(diff) / (24 * 60 * 60 / m_currency.difficultyTarget()) << " days) "
      << (diff >= 0 ? std::string("behind") : std::string("ahead")) << "] " << std::endl << "SYNCHRONIZATION started";

    m_logger(Logging::DEBUGGING) << "Remote top block height: " << syncData.current_height << ", id: " << syncData.top_id;
    //let the socket to send response to handshake, but request callback, to let send request data after response
    m_logger(Logging::TRACE) << context << "requesting synchronization";
    context.m_state = CryptoNoteConnectionContext::state_sync_required;
  }

  updateObservedHeight(syncData.current_height, context);
  context.m_remote_blockchain_height = syncData.current_height;

  if (is_initial) {
    m_peerCount++;
    m_observerManager.notify(&ICryptoNoteProtocolObserver::peerCountUpdated, m_peerCount.load());
  }

  return true;
}

bool CryptoNoteProtocolHandler::removeObserver(ICryptoNoteProtocolObserver* observer)
{
  return m_observerManager.remove(observer);
}

void CryptoNoteProtocolHandler::requestMissingPoolTransactions(const CryptoNoteConnectionContext& context)
{

  // Send a request to a peer node for information about the peer node's mempool

  if (context.m_version < P2PProtocolVersion::V1) {
    return;
  }

  std::vector<Transaction> poolTxs = m_core.getPoolTransactions();

  NOTIFY_REQUEST_TX_POOL::request notification;
  for (const Transaction& tx : poolTxs) {
    notification.txs.emplace_back(getObjectHash(tx));
  }

  bool ok = post_notify<NOTIFY_REQUEST_TX_POOL>(*m_p2p, notification, context);
  if (!ok) {
    m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to post notification NOTIFY_REQUEST_TX_POOL to " << context.m_connection_id;
  }
}

void CryptoNoteProtocolHandler::set_p2p_endpoint(IP2pEndpoint* p2p)
{
  if (p2p)
  {
    m_p2p = p2p;
  }
  else
  {
    m_p2p = &m_p2p_stub;
  }
}

bool CryptoNoteProtocolHandler::start_sync(const CryptoNoteConnectionContext& context)
{
  m_logger(Logging::TRACE) << context << "Starting synchronization";

  if (context.m_state == CryptoNoteConnectionContext::state_synchronizing) {
    assert(context.m_needed_objects.empty());
    assert(context.m_requested_objects.empty());

    // Let the peer node know what blocks we already have in our blockchain so that the peer node knows which new blocks to send to us
    NOTIFY_REQUEST_CHAIN::request request = boost::value_initialized<NOTIFY_REQUEST_CHAIN::request>();
    request.block_ids = m_core.buildSparseChain();
    m_logger(Logging::TRACE) << context << "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << request.block_ids.size();
    post_notify<NOTIFY_REQUEST_CHAIN>(*m_p2p, request, context);
  }

  return true;
}

void CryptoNoteProtocolHandler::stop()
{
  m_stop = true;
}


// Private functions


uint32_t CryptoNoteProtocolHandler::get_current_blockchain_height()
{
  return m_core.get_current_blockchain_height();
}

int CryptoNoteProtocolHandler::handle_request_mempool(int command, const NOTIFY_REQUEST_TX_POOL::request& request, CryptoNoteConnectionContext& context)
{

  // A peer node is requesting new mempool transactions from our node

  m_logger(Logging::TRACE) << context << "NOTIFY_REQUEST_TX_POOL: txs.size() = " << request.txs.size();

  std::vector<Transaction> addedTransactions;
  std::vector<Crypto::Hash> deletedTransactionsIgnore;
  // request.txs contains hashes of all transactions in the peer node's mempool
  m_core.getPoolChanges(request.txs, addedTransactions, deletedTransactionsIgnore);

  // Respond to the peer node with transactions present in our mempool that are not present in theirs
  if (!addedTransactions.empty()) {
    NOTIFY_NEW_TRANSACTIONS::request response;
    for (Transaction& tx : addedTransactions) {
      response.txs.push_back(Common::asString(toBinaryArray(tx)));
    }

    bool ok = post_notify<NOTIFY_NEW_TRANSACTIONS>(*m_p2p, response, context);
    if (!ok) {
      m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to post response NOTIFY_NEW_TRANSACTIONS to " << context.m_connection_id;
    }
  }

  return 1;
}

int CryptoNoteProtocolHandler::handle_notify_new_block(int command, NOTIFY_NEW_BLOCK::request& notification, CryptoNoteConnectionContext& context)
{

  // A peer node is sending new block information to our node

  m_logger(Logging::TRACE) << context << "NOTIFY_NEW_BLOCK (hop " << notification.hop << ")";

  updateObservedHeight(notification.current_blockchain_height, context);

  context.m_remote_blockchain_height = notification.current_blockchain_height;

  if (context.m_state != CryptoNoteConnectionContext::state_normal) {
    return 1;
  }

  for (auto it = notification.b.txs.begin(); it != notification.b.txs.end(); it++) {
    tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
    m_core.handle_incoming_tx(Common::asBinaryArray(*it), tvc, true);
    if (tvc.m_verification_failed) {
      m_logger(Logging::INFO) << context << "Block verification failed: transaction verification failed, dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    }
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  m_core.handle_incoming_block_blob(Common::asBinaryArray(notification.b.block), bvc, true, false);
  if (bvc.m_verification_failed) {
    m_logger(Logging::DEBUGGING) << context << "Block verification failed, dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (bvc.m_added_to_main_chain) {
    ++notification.hop;

    //TODO: Add here announce protocol usage

    // Send new block information to all peer nodes except the peer node that sent us the new block information
    relay_post_notify<NOTIFY_NEW_BLOCK>(*m_p2p, notification, &context.m_connection_id);

    if (bvc.m_switched_to_alt_chain) {
      requestMissingPoolTransactions(context);
    }
  } else if (bvc.m_marked_as_orphaned) {
    context.m_state = CryptoNoteConnectionContext::state_synchronizing;

    // Request new blockchain information from the peer node
    NOTIFY_REQUEST_CHAIN::request request = boost::value_initialized<NOTIFY_REQUEST_CHAIN::request>();
    request.block_ids = m_core.buildSparseChain();
    m_logger(Logging::TRACE) << context << "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << request.block_ids.size();
    post_notify<NOTIFY_REQUEST_CHAIN>(*m_p2p, request, context);
  }

  return 1;
}

int CryptoNoteProtocolHandler::handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& notification, CryptoNoteConnectionContext& context)
{

  // A peer node is sending new transactions to our node

  m_logger(Logging::TRACE) << context << "NOTIFY_NEW_TRANSACTIONS";
  if (context.m_state != CryptoNoteConnectionContext::state_normal)
  {
    return 1;
  }

  for (auto it = notification.txs.begin(); it != notification.txs.end();) {
    tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
    m_core.handle_incoming_tx(Common::asBinaryArray(*it), tvc, false);

    if (tvc.m_verification_failed) {
      m_logger(Logging::INFO) << context << "Tx verification failed";
    }

    if (!tvc.m_verification_failed && tvc.m_should_be_relayed)
    {
      ++it;
    }
    else
    {
      it = notification.txs.erase(it);
    }
  }

  if (notification.txs.size()) {
    //TODO: add announce usage here

    // Send new transactions to all peer nodes except the peer node that sent us the new transactions
    relay_post_notify<NOTIFY_NEW_TRANSACTIONS>(*m_p2p, notification, &context.m_connection_id);
  }

  return true;
}

int CryptoNoteProtocolHandler::handle_request_chain(int command, const NOTIFY_REQUEST_CHAIN::request& request, CryptoNoteConnectionContext& context)
{

  // A peer node is requesting new blocks from our node so they can get synchronized

  m_logger(Logging::TRACE) << context << "NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << request.block_ids.size();

  if (request.block_ids.empty()) {
    m_logger(Logging::ERROR, Logging::BRIGHT_RED) << context << "Failed to handle NOTIFY_REQUEST_CHAIN. block_ids is empty";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (request.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    m_logger(Logging::ERROR) << context << "Failed to handle NOTIFY_REQUEST_CHAIN. block_ids doesn't end with genesis block ID";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  NOTIFY_RESPONSE_CHAIN_ENTRY::request response;
  response.m_block_ids = m_core.findBlockchainSupplement(request.block_ids, BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT, response.total_height, response.start_height);

  m_logger(Logging::TRACE) << context << "-->>NOTIFY_RESPONSE_CHAIN_ENTRY: m_start_height=" << response.start_height << ", m_total_height=" << response.total_height << ", m_block_ids.size()=" << response.m_block_ids.size();
  
  // Respond to the peer with hashes of new blocks
  post_notify<NOTIFY_RESPONSE_CHAIN_ENTRY>(*m_p2p, response, context);
  return 1;
}

int CryptoNoteProtocolHandler::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& request, CryptoNoteConnectionContext& context)
{

  // A peer node is requesting blocks and transactions from our node

  m_logger(Logging::TRACE) << context << "NOTIFY_REQUEST_GET_OBJECTS";

  /* Essentially, one can send such a large amount of IDs that core exhausts
   * all free memory. This issue can theoretically be exploited using very
   * large CN blockchains, such as Monero.
   *
   * This is a partial fix. Thanks and credit given to CryptoNote author
   * 'cryptozoidberg' for collaboration and the fix. Also thanks to
   * 'moneromooo'. Referencing HackerOne report #506595.
   */
  if (request.blocks.size() + request.txs.size() > CRYPTONOTE_PROTOCOL_MAX_OBJECT_REQUEST_COUNT)
  {
    m_logger(Logging::ERROR) << context << "Requested objects count is too big (" << request.blocks.size() << ") expected no more than " << CRYPTONOTE_PROTOCOL_MAX_OBJECT_REQUEST_COUNT;
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  NOTIFY_RESPONSE_GET_OBJECTS::request response;
  if (!m_core.handle_get_objects(request, response)) {
    m_logger(Logging::ERROR) << context << "failed to handle request NOTIFY_REQUEST_GET_OBJECTS, dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
  }
  m_logger(Logging::TRACE) << context << "-->>NOTIFY_RESPONSE_GET_OBJECTS: blocks.size()=" << response.blocks.size() << 
    ", txs.size()=" << response.txs.size() << ", response.m_current_blockchain_height=" << response.current_blockchain_height <<
    ", missed_ids.size()=" << response.missed_ids.size();
  
  // Send blocks and transactions back to peer node
  post_notify<NOTIFY_RESPONSE_GET_OBJECTS>(*m_p2p, response, context);
  return 1;
}

int CryptoNoteProtocolHandler::handle_response_chain_entry(int command, const NOTIFY_RESPONSE_CHAIN_ENTRY::request& response, CryptoNoteConnectionContext& context)
{

  // A peer node is telling us hashes of new blocks so that we can get synchronized

  m_logger(Logging::TRACE) << context << "NOTIFY_RESPONSE_CHAIN_ENTRY: m_block_ids.size()=" << response.m_block_ids.size()
    << ", m_start_height=" << response.start_height << ", m_total_height=" << response.total_height;

  if (!response.m_block_ids.size()) {
    m_logger(Logging::ERROR) << context << "sent empty m_block_ids, dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (!m_core.have_block(response.m_block_ids.front())) {
    m_logger(Logging::ERROR)
      << context << "sent m_block_ids starting from unknown id: "
      << Common::podToHex(response.m_block_ids.front())
      << " , dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  context.m_remote_blockchain_height = response.total_height;
  context.m_last_response_height = response.start_height + static_cast<uint32_t>(response.m_block_ids.size()) - 1;

  if (context.m_last_response_height > context.m_remote_blockchain_height) {
    m_logger(Logging::ERROR)
      << context
      << "sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with \r\nm_total_height="
      << response.total_height << "\r\nm_start_height=" << response.start_height
      << "\r\nm_block_ids.size()=" << response.m_block_ids.size();
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
  }

  for (const Crypto::Hash& blockHash : response.m_block_ids) {
    if (!m_core.have_block(blockHash))
      context.m_needed_objects.push_back(blockHash);
  }

  request_needed_objects(context, false);
  return 1;
}

int CryptoNoteProtocolHandler::handle_response_get_objects(int command, const NOTIFY_RESPONSE_GET_OBJECTS::request& response, CryptoNoteConnectionContext& context)
{

  // A peer node is sending our node new blocks and transactions so that our node can get synchronized

  m_logger(Logging::TRACE) << context << "NOTIFY_RESPONSE_GET_OBJECTS";

  if (context.m_last_response_height > response.current_blockchain_height) {
    m_logger(Logging::ERROR) << context << "sent wrong NOTIFY_HAVE_OBJECTS: response.m_current_blockchain_height=" << response.current_blockchain_height
      << " < m_last_response_height=" << context.m_last_response_height << ", dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  updateObservedHeight(response.current_blockchain_height, context);

  context.m_remote_blockchain_height = response.current_blockchain_height;

  size_t count = 0;
  for (const block_complete_entry& blockCompleteEntry : response.blocks) {
    ++count;
    Block block;
    if (!fromBinaryArray(block, Common::asBinaryArray(blockCompleteEntry.block))) {
      m_logger(Logging::ERROR) << context << "sent wrong block: failed to parse and validate block: \r\n"
        << Common::toHex(Common::asBinaryArray(blockCompleteEntry.block)) << "\r\n dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    }

    Crypto::Hash blockHash = get_block_hash(block);

    //to avoid concurrency in core between connections, suspend connections which delivered block later then first one
    if (count == 2) {
      if (m_core.have_block(blockHash)) {
        context.m_state = CryptoNoteConnectionContext::state_idle;
        context.m_needed_objects.clear();
        context.m_requested_objects.clear();
        m_logger(Logging::DEBUGGING) << context << "Connection set to idle state.";
        return 1;
      }
    }

    auto it = context.m_requested_objects.find(blockHash);
    if (it == context.m_requested_objects.end()) {
      m_logger(Logging::ERROR) << context << "sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id=" << Common::podToHex(blockHash)
        << " wasn't requested, dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    }

    if (block.transactionHashes.size() != blockCompleteEntry.txs.size()) {
      m_logger(Logging::ERROR) << context << "sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id=" << Common::podToHex(blockHash)
        << ", transactionHashes.size()=" << block.transactionHashes.size() << " mismatch with block_complete_entry.m_txs.size()=" << blockCompleteEntry.txs.size() << ", dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    }

    context.m_requested_objects.erase(it);
  }

  if (context.m_requested_objects.size()) {
    m_logger(Logging::ERROR, Logging::BRIGHT_RED) << context <<
      "returned not all requested objects (context.m_requested_objects.size()="
      << context.m_requested_objects.size() << "), dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  {
    m_core.pause_mining();

    BOOST_SCOPE_EXIT_ALL(this) { m_core.update_block_template_and_resume_mining(); };

    int result = processObjects(context, response.blocks);
    if (result != 0) {
      return result;
    }
  }

  uint32_t blockchainHeight = m_core.get_current_blockchain_height();
  m_logger(Logging::DEBUGGING, Logging::BRIGHT_GREEN) << "Local blockchain updated, new height = " << blockchainHeight;

  // Keep asking the peer for more blocks and transactions
  if (!m_stop && context.m_state == CryptoNoteConnectionContext::state_synchronizing) {
    request_needed_objects(context, true);
  }

  return 1;
}

bool CryptoNoteProtocolHandler::on_connection_synchronized()
{
  bool val_expected = false;
  if (m_synchronized.compare_exchange_strong(val_expected, true)) {
    m_logger(Logging::INFO) << ENDL << "**********************************************************************" << ENDL
      << "You are now synchronized with the network. You may now start simplewallet." << ENDL
      << ENDL
      << "Please note, that the blockchain will be saved only after you quit the daemon with \"exit\" command or if you use \"save\" command." << ENDL
      << "Otherwise, you will possibly need to synchronize the blockchain again." << ENDL
      << ENDL
      << "Use \"help\" command to see the list of available commands." << ENDL
      << "**********************************************************************";
    m_core.on_synchronized();

    uint32_t blockchainHeight = m_core.get_current_blockchain_height();
    m_observerManager.notify(&ICryptoNoteProtocolObserver::blockchainSynchronized, blockchainHeight);
  }
  return true;
}

int CryptoNoteProtocolHandler::processObjects(CryptoNoteConnectionContext& context, const std::vector<block_complete_entry>& blocks)
{

  // Sends blocks and transactions to Core for processing

  for (const block_complete_entry& blockCompleteEntry : blocks) {
    if (m_stop) {
      break;
    }

    //process transactions
    for (const std::string& tx_blob : blockCompleteEntry.txs) {
      tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
      m_core.handle_incoming_tx(Common::asBinaryArray(tx_blob), tvc, true);
      if (tvc.m_verification_failed) {
        m_logger(Logging::ERROR) << context << "transaction verification failed on NOTIFY_RESPONSE_GET_OBJECTS, \r\ntx_id = "
          << Common::podToHex(getBinaryArrayHash(Common::asBinaryArray(tx_blob))) << ", dropping connection";
        context.m_state = CryptoNoteConnectionContext::state_shutdown;
        return 1;
      }
    }

    // process block
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    m_core.handle_incoming_block_blob(Common::asBinaryArray(blockCompleteEntry.block), bvc, false, false);

    if (bvc.m_verification_failed) {
      m_logger(Logging::DEBUGGING) << context << "Block verification failed, dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    } else if (bvc.m_marked_as_orphaned) {
      m_logger(Logging::INFO) << context << "Block received at sync phase was marked as orphaned, dropping connection";
      context.m_state = CryptoNoteConnectionContext::state_shutdown;
      return 1;
    } else if (bvc.m_already_exists) {
      m_logger(Logging::DEBUGGING) << context << "Block already exists, switching to idle state";
      context.m_state = CryptoNoteConnectionContext::state_idle;
      context.m_needed_objects.clear();
      context.m_requested_objects.clear();
      return 1;
    }

    m_dispatcher.yield();
  }

  return 0;

}

void CryptoNoteProtocolHandler::recalculateMaxObservedHeight(const boost::uuids::uuid& connectionId)
{
  //should be locked outside
  uint32_t peerHeight = 0;
  m_p2p->for_each_connection([&peerHeight, &connectionId](const CryptoNoteConnectionContext& context, PeerIdType peerIdIgnore) {
    if (context.m_connection_id != connectionId) {
      peerHeight = std::max(peerHeight, context.m_remote_blockchain_height);
    }
  });

  uint32_t localHeight = m_core.get_current_blockchain_height();
  m_observedHeight = std::max(peerHeight, localHeight + 1);
}

void CryptoNoteProtocolHandler::relay_block(NOTIFY_NEW_BLOCK::request& notification)
{
  auto buffer = LevinProtocol::encode(notification);
  m_p2p->externalRelayNotifyToAll(NOTIFY_NEW_BLOCK::ID, buffer);
}

void CryptoNoteProtocolHandler::relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& notification)
{
  auto buffer = LevinProtocol::encode(notification);
  m_p2p->externalRelayNotifyToAll(NOTIFY_NEW_TRANSACTIONS::ID, buffer);
}

bool CryptoNoteProtocolHandler::request_needed_objects(CryptoNoteConnectionContext& context, bool checkAlreadyHaveBlock)
{
  if (context.m_needed_objects.size())
  {
    //we know objects that we need, request this objects
    NOTIFY_REQUEST_GET_OBJECTS::request request;
    size_t count = 0;
    auto it = context.m_needed_objects.begin();

    while (it != context.m_needed_objects.end() && count < BLOCKS_SYNCHRONIZING_DEFAULT_COUNT) {
      if (!(checkAlreadyHaveBlock && m_core.have_block(*it))) {
        request.blocks.push_back(*it);
        ++count;
        context.m_requested_objects.insert(*it);
      }
      it = context.m_needed_objects.erase(it);
    }

    m_logger(Logging::TRACE) << context << "-->>NOTIFY_REQUEST_GET_OBJECTS: blocks.size()=" << request.blocks.size() << ", txs.size()=" << request.txs.size();
    post_notify<NOTIFY_REQUEST_GET_OBJECTS>(*m_p2p, request, context);
  }
  else if (context.m_last_response_height < context.m_remote_blockchain_height - 1) // peer node still has blocks in its blockchain that we don't have in our blockchain, request more blocks from peer node
  {
    NOTIFY_REQUEST_CHAIN::request request = boost::value_initialized<NOTIFY_REQUEST_CHAIN::request>();
    request.block_ids = m_core.buildSparseChain();
    m_logger(Logging::TRACE) << context << "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << request.block_ids.size();
    post_notify<NOTIFY_REQUEST_CHAIN>(*m_p2p, request, context);
  }
  else
  {
    if (!(context.m_last_response_height == context.m_remote_blockchain_height - 1 &&
      !context.m_needed_objects.size() && !context.m_requested_objects.size())) {
      m_logger(Logging::ERROR, Logging::BRIGHT_RED)
        << "request_missing_blocks final condition failed!"
        << "\r\nm_last_response_height=" << context.m_last_response_height
        << "\r\nm_remote_blockchain_height=" << context.m_remote_blockchain_height
        << "\r\nm_needed_objects.size()=" << context.m_needed_objects.size()
        << "\r\nm_requested_objects.size()=" << context.m_requested_objects.size() 
        << "\r\non connection [" << context << "]";
      return false;
    }

    requestMissingPoolTransactions(context);

    context.m_state = CryptoNoteConnectionContext::state_normal;
    m_logger(Logging::INFO, Logging::BRIGHT_GREEN) << context << "SYNCHRONIZED OK";
    on_connection_synchronized();
  }
  return true;
}

void CryptoNoteProtocolHandler::updateObservedHeight(uint32_t peerHeight, const CryptoNoteConnectionContext& context)
{
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(m_observedHeightMutex);

    uint32_t height = m_observedHeight;
    if (peerHeight > context.m_remote_blockchain_height) {
      m_observedHeight = std::max(m_observedHeight, peerHeight);
      if (m_observedHeight != height) {
        updated = true;
      }
    } else if (peerHeight != context.m_remote_blockchain_height && context.m_remote_blockchain_height == m_observedHeight) {
      //the client switched to alternative chain and had maximum observed height. need to recalculate max height
      recalculateMaxObservedHeight(context.m_connection_id);
      if (m_observedHeight != height) {
        updated = true;
      }
    }
  }

  if (updated) {
    m_logger(Logging::TRACE) << "Observed height updated: " << m_observedHeight;
    m_observerManager.notify(&ICryptoNoteProtocolObserver::lastKnownBlockHeightUpdated, m_observedHeight);
  }
}

} // end namespace CryptoNote
