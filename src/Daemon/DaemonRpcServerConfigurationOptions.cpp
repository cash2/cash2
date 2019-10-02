// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DaemonRpcServerConfigurationOptions.h"
#include "Common/CommandLine.h"
#include "CryptoNoteConfig.h"

namespace CryptoNote {

namespace {

const std::string DEFAULT_RPC_IP = "127.0.0.1";
const uint16_t DEFAULT_RPC_PORT = RPC_DEFAULT_PORT;

const command_line::arg_descriptor<std::string> arg_enable_cors     = { "enable-cors", "Adds header 'Access-Control-Allow-Origin' to Daemon RPC responses. Uses the value as domain. Use * for all", "" };
const command_line::arg_descriptor<bool>        arg_restricted_rpc  = { "restricted-rpc", "Restrict Daemon RPC commands to view only commands to prevent abuse" };
const command_line::arg_descriptor<std::string> arg_rpc_bind_ip     = { "rpc-bind-ip", "", DEFAULT_RPC_IP };
const command_line::arg_descriptor<uint16_t>    arg_rpc_bind_port   = { "rpc-bind-port", "", DEFAULT_RPC_PORT };

}

DaemonRpcServerConfigurationOptions::DaemonRpcServerConfigurationOptions() :
  bindIp(DEFAULT_RPC_IP),
  bindPort(DEFAULT_RPC_PORT),
  enableCors(""),
  restrictedRpc(false) {
}

std::string DaemonRpcServerConfigurationOptions::getBindAddress() const {
  return bindIp + ":" + std::to_string(bindPort);
}

void DaemonRpcServerConfigurationOptions::initOptions(boost::program_options::options_description& desc) {
  command_line::add_arg(desc, arg_enable_cors);
  command_line::add_arg(desc, arg_restricted_rpc);
  command_line::add_arg(desc, arg_rpc_bind_ip);
  command_line::add_arg(desc, arg_rpc_bind_port);
}

void DaemonRpcServerConfigurationOptions::init(const boost::program_options::variables_map& vm) {
  enableCors = command_line::get_arg(vm, arg_enable_cors);
  restrictedRpc = command_line::get_arg(vm, arg_restricted_rpc);
  bindIp = command_line::get_arg(vm, arg_rpc_bind_ip);
  bindPort = command_line::get_arg(vm, arg_rpc_bind_port);
}

} // end namespace CryptoNote
