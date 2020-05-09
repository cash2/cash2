// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DaemonConfigurationOptions.h"
#include "Common/CommandLine.h"
#include "Common/Util.h"
#include "CryptoNoteConfig.h"

namespace CryptoNote {

namespace
{

const command_line::arg_descriptor<std::string> arg_config_file =       { "config-file", "Specify the configuration file", std::string(CryptoNote::CRYPTONOTE_NAME) + ".conf" };
const command_line::arg_descriptor<std::string> arg_log_file =          { "log-file", "", "" };
const command_line::arg_descriptor<uint32_t>    arg_log_level =         { "log-level", "", 2 }; // info level
const command_line::arg_descriptor<bool>        arg_no_console =        { "no-console", "Disable daemon console commands" };
const command_line::arg_descriptor<bool>        arg_os_version =        { "os-version", "Shows the Cash2 software version and the OS version" };
const command_line::arg_descriptor<bool>        arg_print_genesis_tx =  { "print-genesis-tx", "Prints genesis block's coinbase transaction as hexidecimal to insert it to config" };
const command_line::arg_descriptor<bool>        arg_testnet =           { "testnet", "Used to deploy test nets. Checkpoints and hardcoded seeds are ignored, network id is changed. Use it with --data-dir flag. The wallet must be launched with --testnet flag.", false };

}

DaemonConfigurationOptions::DaemonConfigurationOptions() :
  configFile(""),
  dataDirectory(""),
  help(false),
  logFile(""),
  logLevel(0),
  noConsole(false),
  osVersion(false),
  printGenesisTransaction(false),
  testnet(false) {
}

void DaemonConfigurationOptions::initOptions(boost::program_options::options_description& desc) {
  command_line::add_arg(desc, arg_config_file);
  command_line::add_arg(desc, command_line::arg_data_dir, Tools::getDefaultDataDirectory());
  command_line::add_arg(desc, command_line::arg_help);
  command_line::add_arg(desc, arg_log_file);
  command_line::add_arg(desc, arg_log_level);
  command_line::add_arg(desc, arg_no_console);
  command_line::add_arg(desc, arg_os_version);
  command_line::add_arg(desc, arg_print_genesis_tx);
  command_line::add_arg(desc, arg_testnet);
  command_line::add_arg(desc, command_line::arg_version);
}

void DaemonConfigurationOptions::init(const boost::program_options::variables_map& vm) {
  configFile = command_line::get_arg(vm, arg_config_file);
  dataDirectory = command_line::get_arg(vm, command_line::arg_data_dir);
  help = command_line::get_arg(vm, command_line::arg_help);
  logFile = command_line::get_arg(vm, arg_log_file);
  logLevel = command_line::get_arg(vm, arg_log_level);
  noConsole = command_line::get_arg(vm, arg_no_console);
  osVersion = command_line::get_arg(vm, arg_os_version);
  printGenesisTransaction = command_line::get_arg(vm, arg_print_genesis_tx);
  testnet = command_line::get_arg(vm, arg_testnet);
}

}