// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <functional>
#include <unordered_map>
#include <boost/functional/hash.hpp>
#include "System/Context.h"
#include "System/ContextGroup.h"
#include "System/Dispatcher.h"
#include "System/Event.h"
#include "System/Timer.h"
#include "System/TcpConnection.h"
#include "System/TcpListener.h"
#include "CryptoNoteCore/OnceInInterval.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Common/CommandLine.h"
#include "Logging/LoggerRef.h"
#include "ConnectionContext.h"
#include "P2pConnectionContext.h"
#include "LevinProtocol.h"
#include "NetNodeCommon.h"
#include "NetNodeConfig.h"
#include "P2pProtocolDefinitions.h"
#include "P2pNetworks.h"
#include "PeerListManager.h"

namespace CryptoNote
{

class NodeServer :  public IP2pEndpoint
{
public:
  NodeServer(System::Dispatcher& dispatcher, CryptoNote::CryptoNoteProtocolHandler& payload_handler, Logging::ILogger& log);
  
  bool deinit();
  CryptoNote::PeerlistManager& getPeerlistManager() { return m_peerlist_manager; }
  virtual uint64_t get_connections_count() override;
  size_t get_outgoing_connections_count();
  CryptoNote::CryptoNoteProtocolHandler& get_payload_object();
  uint32_t get_this_peer_port(){return m_listeningPort;}
  bool init(const NetNodeConfig& config);
  static void init_options(boost::program_options::options_description& desc);
  bool log_connections();
  bool log_grey_peerlist();
  bool log_peerlist();
  bool log_white_peerlist();
  bool run();
  bool sendStopSignal();
  void serialize(ISerializer& s);

private:
  void acceptLoop();
  void addPortMapping(Logging::LoggerRef& logger, uint32_t port);
  bool append_net_address(std::vector<NetworkAddress>& nodes, const std::string& addr);
#ifdef ALLOW_DEBUG_COMMANDS
  bool check_trust(const proof_of_trust& tr);
#endif
  bool connect_to_peerlist(const std::vector<NetworkAddress>& peerAddresses);
  void connectionHandler(const boost::uuids::uuid& connectionId, P2pConnectionContext& connection);
  bool connections_maker();
  virtual void externalRelayNotifyToAll(int command, const BinaryArray& data_buff) override;
  bool fix_time_delta(std::list<PeerlistEntry>& local_peerlist, time_t local_time, int64_t& delta);
  void forEachConnection(std::function<void(P2pConnectionContext&)> action);
  virtual void for_each_connection(std::function<void(CryptoNote::CryptoNoteConnectionContext&, PeerIdType)> f) override;
  bool get_local_node_data(basic_node_data& node_data);
  size_t get_random_index_with_fixed_probability(size_t max_index);
  int handleCommand(const LevinProtocol::Command& cmd, BinaryArray& buff_out, P2pConnectionContext& context, bool& handled);
  bool handleConfig(const NetNodeConfig& config);
  bool handleTimedSyncResponse(const BinaryArray& buffer, P2pConnectionContext& context);
  bool handle_command_line(const boost::program_options::variables_map& vm);
#ifdef ALLOW_DEBUG_COMMANDS
  int handle_get_network_state(int command, const COMMAND_REQUEST_NETWORK_STATE::request& request, COMMAND_REQUEST_NETWORK_STATE::response& response, P2pConnectionContext& context);
  int handle_get_peer_id(int command, const COMMAND_REQUEST_PEER_ID::request& request, COMMAND_REQUEST_PEER_ID::response& response, P2pConnectionContext& context);
  int handle_get_stat_info(int command, const COMMAND_REQUEST_STAT_INFO::request& request, COMMAND_REQUEST_STAT_INFO::response& response, P2pConnectionContext& context);
#endif
  int handle_handshake(int command, const COMMAND_HANDSHAKE::request& request, COMMAND_HANDSHAKE::response& response, P2pConnectionContext& context);
  int handle_ping(int command, const COMMAND_PING::request& request, COMMAND_PING::response& response, P2pConnectionContext& context);
  bool handle_remote_peerlist(const std::list<PeerlistEntry>& peerlist, time_t local_time, const CryptoNoteConnectionContext& context);
  int handle_timed_sync(int command, const COMMAND_TIMED_SYNC::request& request, COMMAND_TIMED_SYNC::response& response, P2pConnectionContext& context);
  bool handshake(CryptoNote::LevinProtocol& proto, P2pConnectionContext& context, bool just_take_peerlist = false);
  bool idle_worker();
  bool init_config();
  virtual bool invoke_notify_to_peer(int command, const BinaryArray& req_buff, const CryptoNoteConnectionContext& context) override;
  bool is_addr_connected(const NetworkAddress& peer);  
  bool is_peer_used(const PeerlistEntry& peer);
  bool is_priority_node(const NetworkAddress& address);
  bool make_default_config();
  bool make_expected_connections_count(bool white_list, size_t expected_connections);
  bool make_new_connection_from_peerlist(bool use_white_list);
  void onIdle();
  void on_connection_close(P2pConnectionContext& context);
  void on_connection_new(P2pConnectionContext& context);
  bool parse_peer_from_string(NetworkAddress& address, const std::string& addressString);
  bool parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string>>& arg, std::vector<NetworkAddress>& addresses);
  std::string print_connections_container();
  std::string print_peerlist_to_string(const std::list<PeerlistEntry>& peerList);
  virtual void relay_notify_to_all(int command, const BinaryArray& data_buff, const net_connection_id* excludeConnection) override;
  bool store_config();
  bool timedSync();
  void timedSyncLoop();
  void timeoutLoop();
  bool try_ping(const basic_node_data& node_data, const P2pConnectionContext& context);
  bool try_to_connect_and_handshake_with_new_peer(const NetworkAddress& networkAddress, bool just_take_peerlist = false, uint64_t last_seen_timestamp = 0, bool white = true);
  void writeHandler(P2pConnectionContext& context);

  typedef std::unordered_map<boost::uuids::uuid, P2pConnectionContext, boost::hash<boost::uuids::uuid>> ConnectionContainer;
  typedef ConnectionContainer::iterator ConnectionIterator;
  ConnectionContainer m_connections;

  struct config
  {
    network_config m_net_config;
    uint64_t m_peer_id;

    void serialize(ISerializer& s) {
      KV_MEMBER(m_net_config)
      KV_MEMBER(m_peer_id)
    }
  };

  config m_config;
  std::string m_config_folder;

  bool m_have_address;
  bool m_first_connection_maker_call;
  uint32_t m_listeningPort;
  uint32_t m_external_port;
  uint32_t m_ip_address;
  bool m_allow_local_ip;
  bool m_hide_my_port;
  std::string m_p2p_state_filename;

  System::Dispatcher& m_dispatcher;
  System::ContextGroup m_workingContextGroup;
  System::Event m_stopEvent;
  System::Timer m_idleTimer;
  System::Timer m_timeoutTimer;
  System::TcpListener m_listener;
  Logging::LoggerRef logger;
  std::atomic<bool> m_stop;

  CryptoNoteProtocolHandler& m_payload_handler;
  PeerlistManager m_peerlist_manager;

  OnceInInterval m_connections_maker_interval;
  OnceInInterval m_peerlist_store_interval;
  System::Timer m_timedSyncTimer;

  std::string m_bind_ip;
  std::string m_port;
#ifdef ALLOW_DEBUG_COMMANDS
  uint64_t m_last_stat_request_time;
#endif
  std::vector<NetworkAddress> m_priority_peers;
  std::vector<NetworkAddress> m_exclusive_peers;
  std::vector<NetworkAddress> m_seed_nodes;
  std::list<PeerlistEntry> m_command_line_peers;
  uint64_t m_peer_livetime;
  boost::uuids::uuid m_network_id; // UUID = universally unique identifier
};

} // end namespace CryptoNote
