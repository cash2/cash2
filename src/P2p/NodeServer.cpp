// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <fstream>
#include <boost/foreach.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/utility/value_init.hpp>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include "NodeServer.h"
#include "System/Context.h"
#include "System/ContextGroupTimeout.h"
#include "System/EventLock.h"
#include "System/InterruptedException.h"
#include "System/Ipv4Address.h"
#include "System/Ipv4Resolver.h"
#include "System/TcpListener.h"
#include "System/TcpConnector.h"
#include "version.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Common/Util.h"
#include "crypto/crypto.h"
#include "ConnectionContext.h"
#include "P2pConnectionContext.h"
#include "LevinProtocol.h"
#include "P2pProtocolDefinitions.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"

using namespace Common;
using namespace Logging;
using namespace CryptoNote;

namespace CryptoNote
{

// Public functions

NodeServer::NodeServer(System::Dispatcher& dispatcher, CryptoNote::CryptoNoteProtocolHandler& payload_handler, Logging::ILogger& log) :
  m_dispatcher(dispatcher),
  m_workingContextGroup(dispatcher),
  m_payload_handler(payload_handler),
  m_allow_local_ip(false),
  m_hide_my_port(false),
  m_network_id(CRYPTONOTE_NETWORK),
  logger(log, "node_server"),
  m_stopEvent(m_dispatcher),
  m_idleTimer(m_dispatcher),
  m_timedSyncTimer(m_dispatcher),
  m_timeoutTimer(m_dispatcher),
  m_stop(false),
  m_connections_maker_interval(1),
  m_peerlist_store_interval(60*30, false) {
}

bool NodeServer::deinit()
{
  return store_config();
}

uint64_t NodeServer::get_connections_count()
{
  return m_connections.size();
}

size_t NodeServer::get_outgoing_connections_count()
{
  size_t count = 0;
  for (const auto& connection : m_connections) {
    if (!connection.second.m_is_income)
    {
      ++count;
    }
  }
  return count;
}

CryptoNote::CryptoNoteProtocolHandler& NodeServer::get_payload_object()
{
  return m_payload_handler;
}

bool NodeServer::init(const NodeServerConfig& config)
{
  if (!config.getTestnet()) {
    for (const char* seedAddress : CryptoNote::SEED_NODES) {
      append_net_address(m_seed_nodes, seedAddress);
    }
  } else {
    m_network_id.data[0] += 1;
  }

  if (!handleConfig(config)) { 
    logger(ERROR, BRIGHT_RED) << "Failed to handle command line"; 
    return false; 
  }

  m_config_folder = config.getConfigFolder();
  m_p2p_state_filename = config.getP2pStateFilename();

  if (!init_config()) {
    logger(ERROR, BRIGHT_RED) << "Failed to init config."; 
    return false; 
  }

  if (!m_peerlist_manager.init(m_allow_local_ip)) { 
    logger(ERROR, BRIGHT_RED) << "Failed to init peerlist."; 
    return false; 
  }

  for(PeerlistEntry& peer : m_command_line_peers)
  {
    m_peerlist_manager.append_with_peer_white(peer);
  }
  
  //only in case if we really sure that we have external visible ip
  m_have_address = true;
  m_ip_address = 0;
  m_last_stat_request_time = 0;

  //try to bind
  logger(INFO) << "Binding on " << m_bind_ip << ":" << m_port;
  m_listeningPort = Common::fromString<uint16_t>(m_port);

  m_listener = System::TcpListener(m_dispatcher, System::Ipv4Address(m_bind_ip), static_cast<uint16_t>(m_listeningPort));

  logger(INFO, BRIGHT_GREEN) << "Net service bound to " << m_bind_ip << ":" << m_listeningPort;

  if(m_external_port)
  {
    logger(INFO) << "External port defined as " << m_external_port;
  }

  addPortMapping(logger, m_listeningPort);

  return true;
}

namespace
{
const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_exclusive_node  = {"add-exclusive-node", "Specify list of peers to connect to only. If this option is given the options add-priority-node and seed-node are ignored"};
const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_peer            = {"add-peer", "Manually add peer to local peerlist"};
const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_priority_node   = {"add-priority-node", "Specify list of peers to connect to and attempt to keep the connection open"};
const command_line::arg_descriptor<bool>                      arg_p2p_allow_local_ip      = {"allow-local-ip", "Allow local ip add to peer list, mostly in debug purposes"};
const command_line::arg_descriptor<bool>                      arg_p2p_hide_my_port        = {"hide-my-port", "Do not announce yourself as peerlist candidate", false, true};
const command_line::arg_descriptor<std::string>               arg_p2p_bind_ip             = {"p2p-bind-ip", "Interface for p2p network protocol", "0.0.0.0"};
const command_line::arg_descriptor<std::string>               arg_p2p_bind_port           = {"p2p-bind-port", "Port for p2p network protocol", std::to_string(CryptoNote::P2P_DEFAULT_PORT)};
const command_line::arg_descriptor<uint32_t>                  arg_p2p_external_port       = {"p2p-external-port", "External port for p2p network protocol (if port forwarding used with NAT)", 0};
const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_seed_node           = {"seed-node", "Connect to a node to retrieve peer addresses, and disconnect"};
}

void NodeServer::init_options(boost::program_options::options_description& desc)
{
  command_line::add_arg(desc, arg_p2p_add_exclusive_node);
  command_line::add_arg(desc, arg_p2p_add_peer);
  command_line::add_arg(desc, arg_p2p_add_priority_node);
  command_line::add_arg(desc, arg_p2p_allow_local_ip);
  command_line::add_arg(desc, arg_p2p_hide_my_port);
  command_line::add_arg(desc, arg_p2p_bind_ip);
  command_line::add_arg(desc, arg_p2p_bind_port);
  command_line::add_arg(desc, arg_p2p_external_port);
  command_line::add_arg(desc, arg_p2p_seed_node);
}

void NodeServer::log_connections()
{
  std::stringstream ss;

  ss << '\n' << '\n' << "Connections" << '\n' << '\n' <<
    std::setw(10) << std::left << "In/Out" <<
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(15) << std::left << "Time (secs)" <<
    std::setw(20) << std::left << "State" <<
    std::endl;

  for (const auto& connection : m_connections) {
    ss <<
      std::setw(10) << std::left << std::string(connection.second.m_is_income ? "In" : "Out") <<
      std::setw(20) << std::left << Common::ipAddressToString(connection.second.m_remote_ip) <<
      std::setw(10) << std::left << std::to_string(connection.second.m_remote_port) <<
      std::setw(20) << std::left << std::hex << connection.second.peerId <<
      std::setw(15) << std::left << std::to_string(time(NULL) - connection.second.m_started) <<
      std::setw(20) << std::left << get_protocol_state_string(connection.second.m_state) <<
      std::endl;
  };

  logger(INFO, BRIGHT_CYAN) << ss.str();
}

void NodeServer::log_grey_peerlist()
{
  std::list<PeerlistEntry> whitePeerlistIgnore;
  std::list<PeerlistEntry> greyPeerlist;
  m_peerlist_manager.get_peerlist_full(greyPeerlist, whitePeerlistIgnore);
  std::stringstream ss;

  ss <<
    '\n' << '\n' << "Grey Peerlist" << '\n' << '\n' <<
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(20) << std::left << "Last Seen" << '\n' <<
    print_peerlist_to_string(greyPeerlist) ;

  logger(INFO, BRIGHT_CYAN) << ss.str();
}

void NodeServer::log_incoming_connections()
{
  std::stringstream ss;

  ss << '\n' << '\n' << "Incoming connections" << '\n' << '\n' << 
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(15) << std::left << "Time (secs)" <<
    std::setw(20) << std::left << "State" <<
    '\n';

  bool incomingConnectionFound = false;

  for (const auto& connection : m_connections) {
    if (connection.second.m_is_income == true)
    {
      ss <<
        std::setw(20) << std::left << Common::ipAddressToString(connection.second.m_remote_ip) <<
        std::setw(10) << std::left << std::to_string(connection.second.m_remote_port) <<
        std::setw(20) << std::left << std::hex << connection.second.peerId <<
        std::setw(15) << std::left << std::to_string(time(NULL) - connection.second.m_started) <<
        std::setw(20) << std::left << get_protocol_state_string(connection.second.m_state) <<
        '\n';

      if (incomingConnectionFound == false)
      {
        incomingConnectionFound = true;
      }
    }
  };

  if (incomingConnectionFound == true)
  {
    logger(INFO, BRIGHT_CYAN) << ss.str();
  }
  else
  {
    logger(INFO, BRIGHT_CYAN) << "\n\nIncoming connections : None";
  }
}

void NodeServer::log_outgoing_connections()
{
  std::stringstream ss;

  ss << '\n' << '\n' << "Outgoing connections" << '\n' << '\n' << 
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(15) << std::left << "Time (secs)" <<
    std::setw(20) << std::left << "State" <<
    '\n';

  bool outgoingConnectionFound = false;

  for (const auto& connection : m_connections) {
    if (connection.second.m_is_income == false)
    {
      ss <<
        std::setw(20) << std::left << Common::ipAddressToString(connection.second.m_remote_ip) <<
        std::setw(10) << std::left << std::to_string(connection.second.m_remote_port) <<
        std::setw(20) << std::left << std::hex << connection.second.peerId <<
        std::setw(15) << std::left << std::to_string(time(NULL) - connection.second.m_started) <<
        std::setw(20) << std::left << get_protocol_state_string(connection.second.m_state) <<
        '\n';

      if (outgoingConnectionFound == false)
      {
        outgoingConnectionFound = true;
      }
    }
  };

  if (outgoingConnectionFound == true)
  {
    logger(INFO, BRIGHT_CYAN) << ss.str();
  }
  else
  {
    logger(INFO, BRIGHT_CYAN) << "\n\nOutgoing connections : None";
  }
}

void NodeServer::log_peerlist()
{
  std::list<PeerlistEntry> whitePeerlist;
  std::list<PeerlistEntry> greyPeerlist;
  m_peerlist_manager.get_peerlist_full(greyPeerlist, whitePeerlist);
  std::stringstream ss;
  ss << 
    '\n' << '\n' << "White Peerlist" << '\n' << '\n' <<
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(20) << std::left << "Last Seen" << '\n' <<
    print_peerlist_to_string(whitePeerlist);

  ss <<
    '\n' << "Grey Peerlist" << '\n' << '\n' <<
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(20) << std::left << "Last Seen" << '\n' <<
    print_peerlist_to_string(greyPeerlist) ;
  logger(INFO, BRIGHT_CYAN) << ss.str();
}

void NodeServer::log_white_peerlist()
{
  std::list<PeerlistEntry> whitePeerlist;
  std::list<PeerlistEntry> greyPeerlistIgnore;
  m_peerlist_manager.get_peerlist_full(greyPeerlistIgnore, whitePeerlist);
  std::stringstream ss;

  ss <<
    '\n' << '\n' << "White Peerlist" << '\n' << '\n' <<
    std::setw(20) << std::left << "IP Address" <<
    std::setw(10) << std::left << "Port" <<
    std::setw(20) << std::left << "Peer ID" <<
    std::setw(20) << std::left << "Last Seen" << '\n' <<
    print_peerlist_to_string(whitePeerlist) ;

  logger(INFO, BRIGHT_CYAN) << ss.str();
}

bool NodeServer::run()
{
  logger(INFO) << "Starting NodeServer";

  m_workingContextGroup.spawn(std::bind(&NodeServer::acceptLoop, this));
  m_workingContextGroup.spawn(std::bind(&NodeServer::onIdle, this));
  m_workingContextGroup.spawn(std::bind(&NodeServer::timedSyncLoop, this));
  m_workingContextGroup.spawn(std::bind(&NodeServer::timeoutLoop, this));

  m_stopEvent.wait();

  logger(INFO) << "Stopping NodeServer and its " << m_connections.size() << " connections ...";
  m_workingContextGroup.interrupt();
  m_workingContextGroup.wait();

  logger(INFO) << "NodeServer loop stopped";
  return true;
}

bool NodeServer::sendStopSignal()
{
  m_stop = true;

  m_dispatcher.remoteSpawn([this] {
    m_stopEvent.set();
    m_payload_handler.stop();
  });

  logger(INFO, BRIGHT_YELLOW) << "Stop signal sent";
  return true;
}

void NodeServer::serialize(ISerializer& s)
{
  uint8_t version = 1;
  s(version, "version");
  
  if (version != 1) {
    return;
  }

  s(m_peerlist_manager, "peerlist");
  s(m_config.m_peer_id, "peer_id");
}


// Private functions


void NodeServer::acceptLoop()
{
  while (!m_stop) {
    try {
      P2pConnectionContext context(m_dispatcher, logger.getLogger(), m_listener.accept());
      context.m_connection_id = boost::uuids::random_generator()();
      context.m_is_income = true;
      context.m_started = time(nullptr);

      std::pair<System::Ipv4Address, uint16_t> addressAndPort = context.connection.getPeerAddressAndPort();
      context.m_remote_ip = hostToNetwork(addressAndPort.first.getValue());
      context.m_remote_port = addressAndPort.second;

      auto it = m_connections.emplace(context.m_connection_id, std::move(context)).first;
      const boost::uuids::uuid& connectionId = it->first;
      P2pConnectionContext& contextRef = it->second;

      m_workingContextGroup.spawn(std::bind(&NodeServer::connectionHandler, this, std::cref(connectionId), std::ref(contextRef)));
    } catch (System::InterruptedException&) {
      logger(DEBUGGING) << "acceptLoop() is interrupted";
      break;
    } catch (const std::exception& e) {
      logger(WARNING) << "Exception in acceptLoop: " << e.what();
    }
  }

  logger(DEBUGGING) << "acceptLoop finished";
}

void NodeServer::addPortMapping(Logging::LoggerRef& logger, uint32_t port)
{
  // Add UPnP port mapping
  logger(INFO) << "Attempting to add IGD port mapping.";
  int result;
  UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, 0, &result);
  UPNPUrls urls;
  IGDdatas igdData;
  char lanAddress[64];
  result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
  freeUPNPDevlist(deviceList);
  if (result != 0) {
    if (result == 1) {
      std::ostringstream portString;
      portString << port;
      if (UPNP_AddPortMapping(urls.controlURL, igdData.first.servicetype, portString.str().c_str(),
        portString.str().c_str(), lanAddress, CryptoNote::CRYPTONOTE_NAME, "TCP", 0, "0") != 0) {
        logger(ERROR) << "UPNP_AddPortMapping failed.";
      } else {
        logger(INFO, BRIGHT_GREEN) << "Added IGD port mapping.";
      }
    } else if (result == 2) {
      logger(INFO) << "IGD was found but reported as not connected.";
    } else if (result == 3) {
      logger(INFO) << "UPnP device was found but not recoginzed as IGD.";
    } else {
      logger(ERROR) << "UPNP_GetValidIGD returned an unknown result code.";
    }

    FreeUPNPUrls(&urls);
  } else {
    logger(INFO) << "No IGD was found.";
  }
}

bool NodeServer::append_net_address(std::vector<NetworkAddress>& nodes, const std::string& address)
{
  size_t pos = address.find_last_of(':');

  if (!(std::string::npos != pos && address.length() - 1 != pos && 0 != pos)) {
    logger(ERROR, BRIGHT_RED) << "Failed to parse seed address from string: '" << address << '\'';
    return false;
  }
  
  std::string host = address.substr(0, pos);

  try {
    uint32_t port = Common::fromString<uint32_t>(address.substr(pos + 1));

    System::Ipv4Resolver resolver(m_dispatcher);
    System::Ipv4Address address = resolver.resolve(host);
    nodes.push_back(NetworkAddress{hostToNetwork(address.getValue()), port});

    logger(TRACE) << "Added seed node: " << nodes.back() << " (" << host << ")";

  } catch (const std::exception& e) {
    logger(ERROR, BRIGHT_YELLOW) << "Failed to resolve host name '" << host << "': " << e.what();
    return false;
  }

  return true;
}

#ifdef ALLOW_DEBUG_COMMANDS

bool NodeServer::check_trust(const proof_of_trust &trust)
{
  uint64_t local_time = time(NULL);
  uint64_t time_delata = local_time > trust.time ? local_time - trust.time : trust.time - local_time;

  if (time_delata > 24 * 60 * 60) {
    logger(ERROR) << "check_trust failed to check time conditions, local_time=" << local_time << ", proof_time=" << trust.time;
    return false;
  }

  if (m_last_stat_request_time >= trust.time) {
    logger(ERROR) << "check_trust failed to check time conditions, last_stat_request_time=" << m_last_stat_request_time << ", proof_time=" << trust.time;
    return false;
  }

  if (m_config.m_peer_id != trust.peer_id) {
    logger(ERROR) << "check_trust failed: peer_id mismatch (passed " << trust.peer_id << ", expected " << m_config.m_peer_id << ")";
    return false;
  }

  Crypto::PublicKey pubicKey;
  Common::podFromHex(CryptoNote::P2P_STAT_TRUSTED_PUB_KEY, pubicKey);
  Crypto::Hash trustHash = get_proof_of_trust_hash(trust);
  if (!Crypto::check_signature(trustHash, pubicKey, trust.sign)) {
    logger(ERROR) << "check_trust failed: sign check failed";
    return false;
  }

  //update last request time
  m_last_stat_request_time = trust.time;
  return true;
}

#endif

bool NodeServer::connect_to_peerlist(const std::vector<NetworkAddress>& peerAddresses)
{
  for(const NetworkAddress& peerAddress: peerAddresses) {
    if (!is_addr_connected(peerAddress)) {
      try_to_connect_and_handshake_with_new_peer(peerAddress);
    }
  }

  return true;
}

void NodeServer::connectionHandler(const boost::uuids::uuid& connectionId, P2pConnectionContext& ctx)
{
  // This inner context is necessary in order to stop connection handler at any moment
  System::Context<> context(m_dispatcher, [this, &connectionId, &ctx] {
    System::Context<> writeContext(m_dispatcher, std::bind(&NodeServer::writeHandler, this, std::ref(ctx)));

    try {
      on_connection_new(ctx);

      LevinProtocol protocol(ctx.connection);
      LevinProtocol::Command command;

      for (;;) {
        if (ctx.m_state == CryptoNoteConnectionContext::state_sync_required) {
          ctx.m_state = CryptoNoteConnectionContext::state_synchronizing;
          m_payload_handler.start_sync(ctx);
        } else if (ctx.m_state == CryptoNoteConnectionContext::state_pool_sync_required) {
          ctx.m_state = CryptoNoteConnectionContext::state_normal;
          m_payload_handler.requestMissingPoolTransactions(ctx);
        }

        if (!protocol.readCommand(command)) {
          break;
        }

        BinaryArray response;
        bool handled = false;
        auto returnCode = handleCommand(command, response, ctx, handled);

        // send response
        if (command.needReply()) {
          if (!handled) {
            returnCode = static_cast<int32_t>(LevinError::ERROR_CONNECTION_HANDLER_NOT_DEFINED);
            response.clear();
          }

          ctx.pushMessage(P2pMessage(P2pMessage::REPLY, command.command, std::move(response), returnCode));
        }

        if (ctx.m_state == CryptoNoteConnectionContext::state_shutdown) {
          break;
        }
      }
    } catch (System::InterruptedException&) {
      logger(DEBUGGING) << ctx << "connectionHandler() inner context is interrupted";
    } catch (std::exception& e) {
      logger(TRACE) << ctx << "Exception in connectionHandler: " << e.what();
    }

    ctx.interrupt();
    writeContext.interrupt();
    writeContext.get();

    on_connection_close(ctx);
    m_connections.erase(connectionId);
  });

  ctx.context = &context;

  try {
    context.get();
  } catch (System::InterruptedException&) {
    logger(DEBUGGING) << "connectionHandler() is interrupted";
  }
}

bool NodeServer::connections_maker()
{
  if (!connect_to_peerlist(m_exclusive_peers)) {
    return false;
  }

  if (!m_exclusive_peers.empty()) {
    return true;
  }

  // connect to seed nodes
  if (!m_peerlist_manager.get_white_peers_count() && m_seed_nodes.size()) {
    size_t try_count = 0;
    size_t current_index = Crypto::rand<size_t>() % m_seed_nodes.size();
    
    while(true) {
      if (try_to_connect_and_handshake_with_new_peer(m_seed_nodes[current_index], true))
      {
        break;
      }

      if (++try_count > m_seed_nodes.size()) {
        logger(ERROR) << "Failed to connect to any of seed peers, continuing without seeds";
        break;
      }

      if(++current_index >= m_seed_nodes.size())
      {
        current_index = 0;
      }
    }
  }

  if (!connect_to_peerlist(m_priority_peers))
  {
    return false;
  }

  size_t expected_white_connections = (m_config.m_net_config.connections_count * CryptoNote::P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT) / 100;

  size_t outgoing_connections_count = get_outgoing_connections_count();
  if (outgoing_connections_count < m_config.m_net_config.connections_count)
  {
    if (outgoing_connections_count < expected_white_connections)
    {
      //start from white list
      if (!make_expected_connections_count(true, expected_white_connections))
      {
        return false;
      }
      //and then do grey list
      if (!make_expected_connections_count(false, m_config.m_net_config.connections_count))
      {
        return false;
      }
    }
    else
    {
      //start from grey list
      if (!make_expected_connections_count(false, m_config.m_net_config.connections_count))
      {
        return false;
      }
      //and then do white list
      if (!make_expected_connections_count(true, m_config.m_net_config.connections_count))
      {
        return false;
      }
    }
  }

  return true;
}

void NodeServer::externalRelayNotifyToAll(int command, const BinaryArray& data_buff)
{
  m_dispatcher.remoteSpawn([this, command, data_buff] {
    relay_notify_to_all(command, data_buff, nullptr);
  });
}

bool NodeServer::fix_time_delta(std::list<PeerlistEntry>& local_peerlist, time_t local_time, int64_t& delta)
{
  //fix time delta
  time_t now = 0;
  time(&now);
  delta = now - local_time;

  for (PeerlistEntry& peer : local_peerlist)
  {
    if (peer.last_seen > uint64_t(local_time))
    {
      logger(ERROR) << "FOUND FUTURE peerlist for entry " << peer.adr << " last_seen: " << peer.last_seen << ", local_time(on remote node):" << local_time;
      return false;
    }

    peer.last_seen += delta;
  }

  return true;
}

void NodeServer::forEachConnection(std::function<void(P2pConnectionContext&)> action)
{

  // create copy of connection ids because the list can be changed during action
  std::vector<boost::uuids::uuid> connectionIds;
  connectionIds.reserve(m_connections.size());
  for (const auto& connection : m_connections) {
    connectionIds.push_back(connection.first);
  }

  for (const auto& connectionId : connectionIds) {
    auto it = m_connections.find(connectionId);
    if (it != m_connections.end()) {
      action(it->second);
    }
  }
}

void NodeServer::for_each_connection(std::function<void(CryptoNoteConnectionContext&, PeerIdType)> f)
{
  for (auto& ctx : m_connections) {
    f(ctx.second, ctx.second.peerId);
  }
}

bool NodeServer::get_local_node_data(basic_node_data& node_data)
{
  node_data.version = P2PProtocolVersion::CURRENT;
  time_t local_time;
  time(&local_time);
  node_data.local_time = local_time;
  node_data.peer_id = m_config.m_peer_id;
  if (!m_hide_my_port)
  {
    node_data.my_port = m_external_port ? m_external_port : m_listeningPort;
  }
  else
  {
    node_data.my_port = 0;
  }

  node_data.network_id = m_network_id;

  return true;
}

size_t NodeServer::get_random_index_with_fixed_probability(size_t max_index)
{
  //divide by zero workaround
  if (!max_index)
  {
    return 0;
  }

  size_t x = Crypto::rand<size_t>() % (max_index + 1);
  return (x*x*x) / (max_index*max_index); //parabola \/
}

template <typename Command, typename Handler>
int invokeAdaptor(const BinaryArray& reqBuf, BinaryArray& resBuf, P2pConnectionContext& ctx, Handler handler)
{
  typedef typename Command::request Request;
  typedef typename Command::response Response;
  int command = Command::ID;

  Request req = boost::value_initialized<Request>();

  if (!LevinProtocol::decode(reqBuf, req)) {
    throw std::runtime_error("Failed to load_from_binary in command " + std::to_string(command));
  }

  Response res = boost::value_initialized<Response>();
  int ret = handler(command, req, res, ctx);
  resBuf = LevinProtocol::encode(res);
  return ret;
}

#define INVOKE_HANDLER(CMD, Handler) case CMD::ID: { ret = invokeAdaptor<CMD>(cmd.buf, out, ctx,  boost::bind(Handler, this, _1, _2, _3, _4)); break; }

int NodeServer::handleCommand(const LevinProtocol::Command& cmd, BinaryArray& out, P2pConnectionContext& ctx, bool& handled)
{
  int ret = 0;
  handled = true;

  if (cmd.isResponse && cmd.command == COMMAND_TIMED_SYNC::ID) {
    if (!handleTimedSyncResponse(cmd.buf, ctx)) {
      // invalid response, close connection
      ctx.m_state = CryptoNoteConnectionContext::state_shutdown;
    }
    return 0;
  }

  switch (cmd.command) {
    INVOKE_HANDLER(COMMAND_HANDSHAKE, &NodeServer::handle_handshake)
    INVOKE_HANDLER(COMMAND_TIMED_SYNC, &NodeServer::handle_timed_sync)
    INVOKE_HANDLER(COMMAND_PING, &NodeServer::handle_ping)
#ifdef ALLOW_DEBUG_COMMANDS
    INVOKE_HANDLER(COMMAND_REQUEST_STAT_INFO, &NodeServer::handle_get_stat_info)
    INVOKE_HANDLER(COMMAND_REQUEST_NETWORK_STATE, &NodeServer::handle_get_network_state)
    INVOKE_HANDLER(COMMAND_REQUEST_PEER_ID, &NodeServer::handle_get_peer_id)
#endif
  default: {
      handled = false;
      ret = m_payload_handler.handleCommand(cmd.isNotify, cmd.command, cmd.buf, out, ctx, handled);
    }
  }

  return ret;
}

#undef INVOKE_HANDLER

bool NodeServer::handleConfig(const NodeServerConfig& config)
{
  m_bind_ip = config.getBindIp();
  m_port = std::to_string(config.getBindPort());
  m_external_port = config.getExternalPort();
  m_allow_local_ip = config.getAllowLocalIp();

  std::vector<PeerlistEntry> peers = config.getPeers();
  std::copy(peers.begin(), peers.end(), std::back_inserter(m_command_line_peers));

  std::vector<NetworkAddress> exclusiveNodes = config.getExclusiveNodes();
  std::copy(exclusiveNodes.begin(), exclusiveNodes.end(), std::back_inserter(m_exclusive_peers));

  std::vector<NetworkAddress> priorityNodes = config.getPriorityNodes();
  std::copy(priorityNodes.begin(), priorityNodes.end(), std::back_inserter(m_priority_peers));

  std::vector<NetworkAddress> seedNodes = config.getSeedNodes();
  std::copy(seedNodes.begin(), seedNodes.end(), std::back_inserter(m_seed_nodes));

  m_hide_my_port = config.getHideMyPort();
  return true;
}

bool NodeServer::handleTimedSyncResponse(const BinaryArray& buffer, P2pConnectionContext& context)
{
  COMMAND_TIMED_SYNC::response response;
  if (!LevinProtocol::decode<COMMAND_TIMED_SYNC::response>(buffer, response)) {
    return false;
  }

  if (!handle_remote_peerlist(response.local_peerlist, response.local_time, context)) {
    logger(Logging::ERROR) << context << "COMMAND_TIMED_SYNC: failed to handle_remote_peerlist(...), closing connection.";
    return false;
  }

  if (!context.m_is_income) {
    m_peerlist_manager.set_peer_just_seen(context.peerId, context.m_remote_ip, context.m_remote_port);
  }

  if (!m_payload_handler.process_payload_sync_data(response.payload_data, context, false)) {
    return false;
  }

  return true;
}

bool NodeServer::handle_command_line(const boost::program_options::variables_map& vm)
{
  m_bind_ip = command_line::get_arg(vm, arg_p2p_bind_ip);
  m_port = command_line::get_arg(vm, arg_p2p_bind_port);
  m_external_port = command_line::get_arg(vm, arg_p2p_external_port);
  m_allow_local_ip = command_line::get_arg(vm, arg_p2p_allow_local_ip);

  if (command_line::has_arg(vm, arg_p2p_add_peer))
  {       
    std::vector<std::string> addedPeers = command_line::get_arg(vm, arg_p2p_add_peer);
    for(const std::string& peerString: addedPeers)
    {
      PeerlistEntry pe = boost::value_initialized<PeerlistEntry>();
      pe.id = Crypto::rand<uint64_t>();
      bool r = parse_peer_from_string(pe.adr, peerString);

      if (!(r))
      {
        logger(ERROR, BRIGHT_RED) << "Failed to parse address from string: " << peerString; return false;
      }

      m_command_line_peers.push_back(pe);
    }
  }

  if (command_line::has_arg(vm,arg_p2p_add_exclusive_node)) {
    if (!parse_peers_and_add_to_container(vm, arg_p2p_add_exclusive_node, m_exclusive_peers))
    {
      return false;
    }
  }

  if (command_line::has_arg(vm, arg_p2p_add_priority_node)) {
    if (!parse_peers_and_add_to_container(vm, arg_p2p_add_priority_node, m_priority_peers))
    {
      return false;
    }
  }

  if (command_line::has_arg(vm, arg_p2p_seed_node)) {
    if (!parse_peers_and_add_to_container(vm, arg_p2p_seed_node, m_seed_nodes))
    {
      return false;
    }
  }

  if (command_line::has_arg(vm, arg_p2p_hide_my_port)) {
    m_hide_my_port = true;
  }

  return true;
}

#ifdef ALLOW_DEBUG_COMMANDS

int NodeServer::handle_get_network_state(int command, const COMMAND_REQUEST_NETWORK_STATE::request& request, COMMAND_REQUEST_NETWORK_STATE::response& response, P2pConnectionContext& context)
{
  if(!check_trust(request.tr)) {
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  for (const auto& connection : m_connections) {
    connection_entry ce;
    ce.adr.ip = connection.second.m_remote_ip;
    ce.adr.port = connection.second.m_remote_port;
    ce.id = connection.second.peerId;
    ce.is_income = connection.second.m_is_income;
    response.connections_list.push_back(ce);
  }

  m_peerlist_manager.get_peerlist_full(response.local_peerlist_gray, response.local_peerlist_white);
  response.my_id = m_config.m_peer_id;
  response.local_time = time(NULL);
  return 1;
}

int NodeServer::handle_get_peer_id(int command, const COMMAND_REQUEST_PEER_ID::request& request, COMMAND_REQUEST_PEER_ID::response& response, P2pConnectionContext& context)
{
  response.my_id = m_config.m_peer_id;
  return 1;
}

int NodeServer::handle_get_stat_info(int command, const COMMAND_REQUEST_STAT_INFO::request& request, COMMAND_REQUEST_STAT_INFO::response& response, P2pConnectionContext& context)
{
  if(!check_trust(request.tr)) {
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }
  response.connections_count = get_connections_count();
  response.incoming_connections_count = response.connections_count - get_outgoing_connections_count();
  response.version = PROJECT_VERSION_LONG;
  response.os_version = Tools::get_os_version_string();
  m_payload_handler.get_stat_info(response.payload_info);
  return 1;
}

#endif

int NodeServer::handle_handshake(int command, const COMMAND_HANDSHAKE::request& request, COMMAND_HANDSHAKE::response& response, P2pConnectionContext& context)
{

  // a peer node is requesting to handshake with our node

  context.m_version = request.node_data.version;

  if (request.node_data.network_id != m_network_id) {
    logger(Logging::INFO) << context << "WRONG NETWORK AGENT CONNECTED! id=" << request.node_data.network_id;
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (!context.m_is_income) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE came not from incoming connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (context.peerId) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE came, but seems that connection already have associated peer_id (double COMMAND_HANDSHAKE?)";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  if (!m_payload_handler.process_payload_sync_data(request.payload_data, context, true)) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE came, but process_payload_sync_data returned false, dropping connection.";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }
  //associate peer_id with this connection
  context.peerId = request.node_data.peer_id;

  if (request.node_data.peer_id != m_config.m_peer_id && request.node_data.my_port) {
    PeerIdType peer_id_l = request.node_data.peer_id;
    uint32_t port_l = request.node_data.my_port;

    if (try_ping(request.node_data, context)) {
      //called only(!) if success pinged, update local peerlist
      PeerlistEntry pe;
      pe.adr.ip = context.m_remote_ip;
      pe.adr.port = port_l;
      pe.last_seen = time(nullptr);
      pe.id = peer_id_l;
      m_peerlist_manager.append_with_peer_white(pe);

      logger(Logging::TRACE) << context << "BACK PING SUCCESS, " << Common::ipAddressToString(context.m_remote_ip) << ":" << port_l << " added to whitelist";
    }
  }

  //fill response
  m_peerlist_manager.get_peerlist_head(response.local_peerlist);
  get_local_node_data(response.node_data);
  m_payload_handler.get_payload_sync_data(response.payload_data);

  logger(Logging::DEBUGGING, Logging::BRIGHT_GREEN) << "COMMAND_HANDSHAKE";
  return 1;
}

int NodeServer::handle_ping(int command, const COMMAND_PING::request& request, COMMAND_PING::response& response, P2pConnectionContext& context)
{
  logger(Logging::TRACE) << context << "COMMAND_PING";
  response.status = PING_OK_RESPONSE_STATUS_TEXT;
  response.peer_id = m_config.m_peer_id;
  return 1;
}

bool NodeServer::handle_remote_peerlist(const std::list<PeerlistEntry>& peerlist, time_t local_time, const CryptoNoteConnectionContext& context)
{
  int64_t delta = 0;
  std::list<PeerlistEntry> peerlist_ = peerlist;
  if (!fix_time_delta(peerlist_, local_time, delta))
  {
    return false;
  }

  logger(Logging::TRACE) << context << "REMOTE PEERLIST: TIME_DELTA: " << delta << ", remote peerlist size=" << peerlist_.size();
  logger(Logging::TRACE) << context << "REMOTE PEERLIST: " <<  print_peerlist_to_string(peerlist_);
  return m_peerlist_manager.merge_peerlist(peerlist_);
}

int NodeServer::handle_timed_sync(int command, const COMMAND_TIMED_SYNC::request& request, COMMAND_TIMED_SYNC::response& response, P2pConnectionContext& context)
{
  if(!m_payload_handler.process_payload_sync_data(request.payload_data, context, false)) {
    logger(Logging::ERROR) << context << "Failed to process_payload_sync_data(), dropping connection";
    context.m_state = CryptoNoteConnectionContext::state_shutdown;
    return 1;
  }

  //fill response
  response.local_time = time(NULL);
  m_peerlist_manager.get_peerlist_head(response.local_peerlist);
  m_payload_handler.get_payload_sync_data(response.payload_data);
  logger(Logging::TRACE) << context << "COMMAND_TIMED_SYNC";
  return 1;
}

bool NodeServer::handshake(CryptoNote::LevinProtocol& levinProtocol, P2pConnectionContext& context, bool just_take_peerlist)
{
  COMMAND_HANDSHAKE::request request;
  COMMAND_HANDSHAKE::response response;
  get_local_node_data(request.node_data);
  m_payload_handler.get_payload_sync_data(request.payload_data);

  if (!levinProtocol.invoke(COMMAND_HANDSHAKE::ID, request, response)) {
    logger(Logging::ERROR) << context << "Failed to invoke COMMAND_HANDSHAKE, closing connection.";
    return false;
  }

  context.m_version = response.node_data.version;

  if (response.node_data.network_id != m_network_id) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE Failed, wrong network!  (" << response.node_data.network_id << "), closing connection.";
    return false;
  }

  if (!handle_remote_peerlist(response.local_peerlist, response.node_data.local_time, context)) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE: failed to handle_remote_peerlist(...), closing connection.";
    return false;
  }

  if (just_take_peerlist) {
    return true;
  }

  if (!m_payload_handler.process_payload_sync_data(response.payload_data, context, true)) {
    logger(Logging::ERROR) << context << "COMMAND_HANDSHAKE invoked, but process_payload_sync_data returned false, dropping connection.";
    return false;
  }

  context.peerId = response.node_data.peer_id;
  m_peerlist_manager.set_peer_just_seen(response.node_data.peer_id, context.m_remote_ip, context.m_remote_port);

  if (response.node_data.peer_id == m_config.m_peer_id)  {
    logger(Logging::TRACE) << context << "Connection to self detected, dropping connection";
    return false;
  }

  logger(Logging::DEBUGGING) << context << "COMMAND_HANDSHAKE INVOKED OK";
  return true;
}

bool NodeServer::idle_worker()
{
  try {
    m_connections_maker_interval.call(std::bind(&NodeServer::connections_maker, this));
    m_peerlist_store_interval.call(std::bind(&NodeServer::store_config, this));
  } catch (std::exception& e) {
    logger(DEBUGGING) << "exception in idle_worker: " << e.what();
  }
  return true;
}

bool NodeServer::init_config()
{
  try {
    std::string state_file_path = m_config_folder + "/" + m_p2p_state_filename;
    bool loaded = false;

    try {
      std::ifstream p2p_data;
      p2p_data.open(state_file_path, std::ios_base::binary | std::ios_base::in);

      if (!p2p_data.fail()) {
        StdInputStream inputStream(p2p_data);
        BinaryInputStreamSerializer a(inputStream);
        CryptoNote::serialize(*this, a);
        loaded = true;
      }
    } catch (std::exception&) {
    }

    if (!loaded) {
      make_default_config();
    }

    //at this moment we have hardcoded config
    m_config.m_net_config.handshake_interval = CryptoNote::P2P_DEFAULT_HANDSHAKE_INTERVAL;
    m_config.m_net_config.connections_count = CryptoNote::P2P_DEFAULT_CONNECTIONS_COUNT;
    m_config.m_net_config.packet_max_size = CryptoNote::P2P_DEFAULT_PACKET_MAX_SIZE; //20 MB limit
    m_config.m_net_config.config_id = 0; // initial config
    m_config.m_net_config.connection_timeout = CryptoNote::P2P_DEFAULT_CONNECTION_TIMEOUT;
    m_config.m_net_config.ping_connection_timeout = CryptoNote::P2P_DEFAULT_PING_CONNECTION_TIMEOUT;
    m_config.m_net_config.send_peerlist_sz = CryptoNote::P2P_DEFAULT_PEERS_IN_HANDSHAKE;

    m_first_connection_maker_call = true;
  } catch (const std::exception& e) {
    logger(ERROR) << "init_config failed: " << e.what();
    return false;
  }
  return true;
}

bool NodeServer::invoke_notify_to_peer(int command, const BinaryArray& buffer, const CryptoNoteConnectionContext& context)
{
  auto it = m_connections.find(context.m_connection_id);
  if (it == m_connections.end()) {
    return false;
  }

  it->second.pushMessage(P2pMessage(P2pMessage::NOTIFY, command, buffer));

  return true;
}

bool NodeServer::is_addr_connected(const NetworkAddress& address)
{
  for (const auto& connection : m_connections) {
    if (!connection.second.m_is_income && address.ip == connection.second.m_remote_ip && address.port == connection.second.m_remote_port) {
      return true;
    }
  }
  return false;
}

bool NodeServer::is_peer_used(const PeerlistEntry& peer)
{
  if(m_config.m_peer_id == peer.id)
  {
    return true; //dont make connections to ourself
  }

  for (const auto& connection : m_connections) {
    const auto& context = connection.second;
    if(context.peerId == peer.id || (!context.m_is_income && peer.adr.ip == context.m_remote_ip && peer.adr.port == context.m_remote_port)) {
      return true;
    }
  }

  return false;
}

bool NodeServer::is_priority_node(const NetworkAddress& address)
{
  return 
    (std::find(m_priority_peers.begin(), m_priority_peers.end(), address) != m_priority_peers.end()) || 
    (std::find(m_exclusive_peers.begin(), m_exclusive_peers.end(), address) != m_exclusive_peers.end());
}

bool NodeServer::make_default_config()
{
  m_config.m_peer_id  = Crypto::rand<uint64_t>();
  return true;
}

bool NodeServer::make_expected_connections_count(bool white_list, size_t expected_connections)
{
  size_t outgoing_connections_count = get_outgoing_connections_count();

  //add new connections from white peers
  while (outgoing_connections_count < expected_connections)
  {
    if (m_stopEvent.get())
    {
      return false;
    }

    if (!make_new_connection_from_peerlist(white_list))
    {
      break;
    }

    outgoing_connections_count = get_outgoing_connections_count();
  }

  return true;
}

bool NodeServer::make_new_connection_from_peerlist(bool use_white_list)
{
  size_t local_peers_count = use_white_list ? m_peerlist_manager.get_white_peers_count():m_peerlist_manager.get_gray_peers_count();
  
  if (local_peers_count == 0)
  {
    return false; // no peers
  }

  size_t max_random_index = std::min<uint64_t>(local_peers_count - 1, 20); // 20 - magic number alert

  std::set<size_t> tried_peer_indexes;

  size_t try_count = 0;
  size_t rand_count = 0;
  while(rand_count < (max_random_index + 1) * 3 && try_count < 10 && !m_stop) { // 10 - magic number alert
    ++rand_count;
    size_t random_index = get_random_index_with_fixed_probability(max_random_index);

    if (!(random_index < local_peers_count)) {
      logger(ERROR, BRIGHT_RED) << "random_starter_index < peers_local.size() failed!!";
      return false;
    }

    if (tried_peer_indexes.count(random_index))
    {
      continue;
    }

    tried_peer_indexes.insert(random_index);
    PeerlistEntry peer = boost::value_initialized<PeerlistEntry>();
    bool r = use_white_list ? m_peerlist_manager.get_white_peer_by_index(peer, random_index):m_peerlist_manager.get_gray_peer_by_index(peer, random_index);
    
    if (!(r))
    {
      logger(ERROR, BRIGHT_RED) << "Failed to get random peer from peerlist(white:" << use_white_list << ")";
      return false;
    }

    ++try_count;

    if (is_peer_used(peer))
    {
      continue;
    }

    logger(DEBUGGING) << "Selected peer: " << peer.id << " " << peer.adr << " [white=" << use_white_list
                  << "] last_seen: " << (peer.last_seen ? Common::timeIntervalToString(time(NULL) - peer.last_seen) : "never");
    
    if (!try_to_connect_and_handshake_with_new_peer(peer.adr, false, peer.last_seen, use_white_list))
    {
      continue;
    }

    return true;
  }

  return false;
}

void NodeServer::onIdle()
{
  logger(DEBUGGING) << "onIdle started";

  try {
    while (!m_stop) {
      idle_worker();
      m_payload_handler.on_idle();
      m_idleTimer.sleep(std::chrono::seconds(1));
    }
  } catch (System::InterruptedException&) {
    logger(DEBUGGING) << "onIdle() is interrupted";
  } catch (std::exception& e) {
    logger(WARNING) << "Exception in onIdle: " << e.what();
  }

  logger(DEBUGGING) << "onIdle finished";
}

void NodeServer::on_connection_close(P2pConnectionContext& context)
{
  logger(TRACE) << context << "CLOSE CONNECTION";
  m_payload_handler.onConnectionClosed(context);
}

void NodeServer::on_connection_new(P2pConnectionContext& context)
{
  logger(TRACE) << context << "NEW CONNECTION";
  m_payload_handler.onConnectionOpened(context);
}

bool NodeServer::parse_peer_from_string(NetworkAddress& address, const std::string& addressString)
{
  return Common::parseIpAddressAndPort(address.ip, address.port, addressString);
}

bool NodeServer::parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string>>& arg, std::vector<NetworkAddress>& addresses)
{
  std::vector<std::string> peerStrings = command_line::get_arg(vm, arg);

  for(const std::string& peerString : peerStrings) {
    NetworkAddress peerAddress;
    if (!parse_peer_from_string(peerAddress, peerString)) { 
      logger(ERROR, BRIGHT_RED) << "Failed to parse address from string: " << peerString; 
      return false; 
    }
    addresses.push_back(peerAddress);
  }

  return true;
}

std::string NodeServer::print_peerlist_to_string(const std::list<PeerlistEntry>& peerList)
{
  time_t now_time = 0;
  time(&now_time);
  std::stringstream ss;
  for (const PeerlistEntry& peerListEntry : peerList) {
    ss << 
    std::setw(20) << std::left << Common::ipAddressToString(peerListEntry.adr.ip) <<
    std::setw(10) << std::left << std::to_string(peerListEntry.adr.port) <<
    std::setw(20) << std::left << std::hex << peerListEntry.id <<
    std::setw(20) << std::left << Common::timeIntervalToString(now_time - peerListEntry.last_seen) << std::endl;
  }
  return ss.str();
}

void NodeServer::relay_notify_to_all(int command, const BinaryArray& buffer, const net_connection_id* excludeConnection)
{
  net_connection_id excludeId = excludeConnection ? *excludeConnection : boost::value_initialized<net_connection_id>();

  forEachConnection([&](P2pConnectionContext& context) {
    if (context.peerId && context.m_connection_id != excludeId &&
        (context.m_state == CryptoNoteConnectionContext::state_normal ||
         context.m_state == CryptoNoteConnectionContext::state_synchronizing)) {
      context.pushMessage(P2pMessage(P2pMessage::NOTIFY, command, buffer));
    }
  });
}

bool NodeServer::store_config()
{
  try {
    if (!Tools::create_directories_if_necessary(m_config_folder)) {
      logger(INFO) << "Failed to create data directory: " << m_config_folder;
      return false;
    }

    std::string state_file_path = m_config_folder + "/" + m_p2p_state_filename;
    std::ofstream p2p_data;
    p2p_data.open(state_file_path, std::ios_base::binary | std::ios_base::out | std::ios::trunc);
    if (p2p_data.fail())  {
      logger(INFO) << "Failed to save config to file " << state_file_path;
      return false;
    };

    StdOutputStream stream(p2p_data);
    BinaryOutputStreamSerializer a(stream);
    CryptoNote::serialize(*this, a);
    return true;
  } catch (const std::exception& e) {
    logger(WARNING) << "store_config failed: " << e.what();
  }

  return false;
}

bool NodeServer::timedSync()
{
  COMMAND_TIMED_SYNC::request request = boost::value_initialized<COMMAND_TIMED_SYNC::request>();
  m_payload_handler.get_payload_sync_data(request.payload_data);
  BinaryArray commandBuffer = LevinProtocol::encode<COMMAND_TIMED_SYNC::request>(request);

  forEachConnection([&](P2pConnectionContext& conn) {
    if (conn.peerId && 
        (conn.m_state == CryptoNoteConnectionContext::state_normal || 
         conn.m_state == CryptoNoteConnectionContext::state_idle)) {
      conn.pushMessage(P2pMessage(P2pMessage::COMMAND, COMMAND_TIMED_SYNC::ID, commandBuffer));
    }
  });

  return true;
}

void NodeServer::timedSyncLoop()
{
  try {
    for (;;) {
      m_timedSyncTimer.sleep(std::chrono::seconds(P2P_DEFAULT_HANDSHAKE_INTERVAL));
      timedSync();
    }
  } catch (System::InterruptedException&) {
    logger(DEBUGGING) << "timedSyncLoop() is interrupted";
  } catch (std::exception& e) {
    logger(WARNING) << "Exception in timedSyncLoop: " << e.what();
  }

  logger(DEBUGGING) << "timedSyncLoop finished";
}

void NodeServer::timeoutLoop()
{
  try {
    while (!m_stop) {
      m_timeoutTimer.sleep(std::chrono::seconds(10));
      auto now = P2pConnectionContext::Clock::now();

      for (auto& connection : m_connections) {
        P2pConnectionContext& context = connection.second;
        if (context.writeDuration(now) > P2P_DEFAULT_INVOKE_TIMEOUT) {
          logger(WARNING) << context << "write operation timed out, stopping connection";
          context.interrupt();
        }
      }
    }
  } catch (System::InterruptedException&) {
    logger(DEBUGGING) << "timeoutLoop() is interrupted";
  } catch (std::exception& e) {
    logger(WARNING) << "Exception in timeoutLoop: " << e.what();
  }
}

bool NodeServer::try_ping(const basic_node_data& node_data, const P2pConnectionContext& context)
{
  if(!node_data.my_port) {
    return false;
  }

  uint32_t actual_ip =  context.m_remote_ip;
  if(!m_peerlist_manager.is_ip_allowed(actual_ip)) {
    return false;
  }

  std::string ip = Common::ipAddressToString(actual_ip);
  uint32_t port = node_data.my_port;
  PeerIdType peerId = node_data.peer_id;

  try {
    COMMAND_PING::request request;
    COMMAND_PING::response response;
    System::Context<> pingContext(m_dispatcher, [&] {
      System::TcpConnector connector(m_dispatcher);
      System::TcpConnection connection = connector.connect(System::Ipv4Address(ip), static_cast<uint16_t>(port));
      LevinProtocol(connection).invoke(COMMAND_PING::ID, request, response);
    });

    System::Context<> timeoutContext(m_dispatcher, [&] {
      System::Timer(m_dispatcher).sleep(std::chrono::milliseconds(m_config.m_net_config.connection_timeout * 2));
      logger(DEBUGGING) << context << "Back ping timed out" << ip << ":" << port;
      pingContext.interrupt();
    });

    pingContext.get();

    if (response.status != PING_OK_RESPONSE_STATUS_TEXT || peerId != response.peer_id) {
      logger(DEBUGGING) << context << "Back ping invoke wrong response \"" << response.status << "\" from" << ip
                                 << ":" << port << ", hsh_peer_id=" << peerId << ", response.peer_id=" << response.peer_id;
      return false;
    }
  } catch (std::exception& e) {
    logger(DEBUGGING) << context << "Back ping connection to " << ip << ":" << port << " failed: " << e.what();
    return false;
  }

  return true;
}

bool NodeServer::try_to_connect_and_handshake_with_new_peer(const NetworkAddress& address, bool just_take_peerlist, uint64_t last_seen_timestamp, bool white)
{
  logger(DEBUGGING) << "Connecting to " << address << " (white=" << white << ", last_seen: "
      << (last_seen_timestamp ? Common::timeIntervalToString(time(NULL) - last_seen_timestamp) : "never") << ")...";

  try {
    System::TcpConnection connection;

    try {
      System::Context<System::TcpConnection> connectionContext(m_dispatcher, [&] {
        System::TcpConnector connector(m_dispatcher);
        return connector.connect(System::Ipv4Address(Common::ipAddressToString(address.ip)), static_cast<uint16_t>(address.port));
      });

      System::Context<> timeoutContext(m_dispatcher, [&] {
        System::Timer(m_dispatcher).sleep(std::chrono::milliseconds(m_config.m_net_config.connection_timeout));
        connectionContext.interrupt();
        logger(DEBUGGING) << "Connection to " << address <<" timed out, interrupt it";
      });

      connection = std::move(connectionContext.get());
    } catch (System::InterruptedException&) {
      logger(DEBUGGING) << "Connection timed out";
      return false;
    }

    P2pConnectionContext context(m_dispatcher, logger.getLogger(), std::move(connection));

    context.m_connection_id = boost::uuids::random_generator()();
    context.m_remote_ip = address.ip;
    context.m_remote_port = address.port;
    context.m_is_income = false;
    context.m_started = time(nullptr);

    try {
      System::Context<bool> handshakeContext(m_dispatcher, [&] {
        CryptoNote::LevinProtocol protocol(context.connection);
        return handshake(protocol, context, just_take_peerlist);
      });

      System::Context<> timeoutContext(m_dispatcher, [&] {
        // Here we use connection_timeout * 3, one for this handshake, and two for back ping from peer.
        System::Timer(m_dispatcher).sleep(std::chrono::milliseconds(m_config.m_net_config.connection_timeout * 3));
        handshakeContext.interrupt();
        logger(DEBUGGING) << "Handshake with " << address << " timed out, interrupt it";
      });

      if (!handshakeContext.get()) {
        logger(WARNING) << "Failed to HANDSHAKE with peer " << address;
        return false;
      }
    } catch (System::InterruptedException&) {
      logger(DEBUGGING) << "Handshake timed out";
      return false;
    }

    if (just_take_peerlist) {
      logger(Logging::DEBUGGING, Logging::BRIGHT_GREEN) << context << "CONNECTION HANDSHAKED OK AND CLOSED.";
      return true;
    }

    PeerlistEntry peer = boost::value_initialized<PeerlistEntry>();
    peer.adr = address;
    peer.id = context.peerId;
    peer.last_seen = time(nullptr);
    m_peerlist_manager.append_with_peer_white(peer);

    if (m_stop) {
      throw System::InterruptedException();
    }

    auto iter = m_connections.emplace(context.m_connection_id, std::move(context)).first;
    const boost::uuids::uuid& connectionId = iter->first;
    P2pConnectionContext& connectionContext = iter->second;

    m_workingContextGroup.spawn(std::bind(&NodeServer::connectionHandler, this, std::cref(connectionId), std::ref(connectionContext)));

    return true;
  } catch (System::InterruptedException&) {
    logger(DEBUGGING) << "Connection process interrupted";
    throw;
  } catch (const std::exception& e) {
    logger(DEBUGGING) << "Connection to " << address << " failed: " << e.what();
  }

  return false;
}

void NodeServer::writeHandler(P2pConnectionContext& context)
{
  logger(DEBUGGING) << context << "writeHandler started";

  try {
    LevinProtocol protocol(context.connection);

    for (;;) {
      std::vector<P2pMessage> messages = context.popBuffer();
      if (messages.empty()) {
        break;
      }

      for (const P2pMessage& message : messages) {
        logger(DEBUGGING) << context << "message " << message.type << ':' << message.command;
        switch (message.type) {
        case P2pMessage::COMMAND:
          protocol.sendMessage(message.command, message.buffer, true);
          break;
        case P2pMessage::NOTIFY:
          protocol.sendMessage(message.command, message.buffer, false);
          break;
        case P2pMessage::REPLY:
          protocol.sendReply(message.command, message.buffer, message.returnCode);
          break;
        default:
          assert(false);
        }
      }
    }
  } catch (System::InterruptedException&) {
    // connection stopped
    logger(DEBUGGING) << context << "writeHandler() is interrupted";
  } catch (std::exception& e) {
    logger(WARNING) << context << "error during write: " << e.what();
    context.interrupt(); // stop connection on write error
  }

  logger(DEBUGGING) << context << "writeHandler finished";
}

} // end namespace CryptoNote
