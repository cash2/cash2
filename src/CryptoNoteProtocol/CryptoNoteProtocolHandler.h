// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include "Common/ObserverManager.h"
#include "../CryptoNoteConfig.h"
#include "CryptoNoteCore/ICore.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolObserver.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/P2pProtocolDefinitions.h"
#include "P2p/NodeServerCommon.h"
#include "P2p/ConnectionContext.h"
#include "P2p/LevinProtocol.h"
#include "Logging/LoggerRef.h"

namespace CryptoNote
{

class CryptoNoteProtocolHandler : public i_cryptonote_protocol, public ICryptoNoteProtocolQuery
{
public:
  CryptoNoteProtocolHandler(const Currency& currency, System::Dispatcher& dispatcher, ICore& core, IP2pEndpoint* p2p, Logging::ILogger& log);
  virtual bool addObserver(ICryptoNoteProtocolObserver* observer) override;
  virtual uint32_t getObservedHeight() const override;
  virtual size_t getPeerCount() const override;
  void get_all_connections_addresses(std::vector<std::string>& addresses);
  void get_incoming_connections_addresses(std::vector<std::string>& addresses);
  void get_outgoing_connections_addresses(std::vector<std::string>& addresses);
  bool get_payload_sync_data(CORE_SYNC_DATA& syncData);
  bool get_stat_info(core_stat_info& info);
  int handleCommand(bool is_notify, int command, const BinaryArray& in, BinaryArray& out, CryptoNoteConnectionContext& ctx, bool& handled);
  virtual bool isSynchronized() const override { return m_synchronized; }
  void onConnectionClosed(const CryptoNoteConnectionContext& context);
  void onConnectionOpened(CryptoNoteConnectionContext& context); // no definition
  bool on_idle();
  bool process_payload_sync_data(const CORE_SYNC_DATA& syncData, CryptoNoteConnectionContext& context, bool is_initial);
  virtual bool removeObserver(ICryptoNoteProtocolObserver* observer) override;
  void requestMissingPoolTransactions(const CryptoNoteConnectionContext& context);
  void set_p2p_endpoint(IP2pEndpoint* p2p);
  bool start_sync(const CryptoNoteConnectionContext& context);
  void stop();

private:
  uint32_t get_current_blockchain_height();
  int handle_request_mempool(int command, const NOTIFY_REQUEST_TX_POOL::request& request, CryptoNoteConnectionContext& context);
  int handle_notify_new_block(int command, NOTIFY_NEW_BLOCK::request& notification, CryptoNoteConnectionContext& context);
  int handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& notification, CryptoNoteConnectionContext& context);
  int handle_request_chain(int command, const NOTIFY_REQUEST_CHAIN::request& request, CryptoNoteConnectionContext& context);
  int handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& request, CryptoNoteConnectionContext& context);
  int handle_response_chain_entry(int command, const NOTIFY_RESPONSE_CHAIN_ENTRY::request& response, CryptoNoteConnectionContext& context);
  int handle_response_get_objects(int command, const NOTIFY_RESPONSE_GET_OBJECTS::request& response, CryptoNoteConnectionContext& context);
  bool on_connection_synchronized();
  int processObjects(CryptoNoteConnectionContext& context, const std::vector<block_complete_entry>& blocks);
  void recalculateMaxObservedHeight(const boost::uuids::uuid& connectionId);
  virtual void relay_block(NOTIFY_NEW_BLOCK::request& notification) override;
  virtual void relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& notification) override;
  bool request_needed_objects(CryptoNoteConnectionContext& context, bool checkAlreadyHaveBlock);
  void updateObservedHeight(uint32_t peerHeight, const CryptoNoteConnectionContext& context);

  // sends information from our node to a specific peer node
  template<class t_parametr>
  bool post_notify(IP2pEndpoint& p2p, typename t_parametr::request& arg, const CryptoNoteConnectionContext& context) {
    return p2p.invoke_notify_to_peer(t_parametr::ID, LevinProtocol::encode(arg), context);
  }

  // sends information from our node to all peer nodes
  template<class t_parametr>
  void relay_post_notify(IP2pEndpoint& p2p, typename t_parametr::request& arg, const net_connection_id* excludeConnection = nullptr) {
    p2p.relay_notify_to_all(t_parametr::ID, LevinProtocol::encode(arg), excludeConnection);
  }

  Logging::LoggerRef m_logger;

  System::Dispatcher& m_dispatcher;
  ICore& m_core;
  const Currency& m_currency;

  p2p_endpoint_stub m_p2p_stub;
  IP2pEndpoint* m_p2p;
  std::atomic<bool> m_synchronized;
  std::atomic<bool> m_stop;

  mutable std::mutex m_observedHeightMutex;
  uint32_t m_observedHeight;

  std::atomic<size_t> m_peerCount;
  Tools::ObserverManager<ICryptoNoteProtocolObserver> m_observerManager;
};

} // end namespace CryptoNote
