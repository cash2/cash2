// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SimpleWalletConfigurationOptions.h"
#include "Common/CommandLine.h"
#include "Common/ConsoleTools.h"
#include "Logging/ILogger.h"
#include "version.h"

namespace CryptoNote {

namespace
{

const command_line::arg_descriptor<std::string> arg_daemon_address =          { "daemon-address", "Use daemon instance at <host>:<port>", "" };
const command_line::arg_descriptor<std::string> arg_daemon_host =             { "daemon-host", "Use daemon instance at host <arg> instead of localhost", "" };
const command_line::arg_descriptor<uint16_t> arg_daemon_port =                { "daemon-port", "Use daemon instance at port <arg> instead of 12276", 0 };
const command_line::arg_descriptor<uint32_t> arg_log_level =                  { "log-level", "", Logging::INFO };
const command_line::arg_descriptor<bool> arg_testnet =                        { "testnet", "Used to deploy test nets. The daemon must be launched with --testnet flag", false };

}

SimpleWalletConfigurationOptions::SimpleWalletConfigurationOptions() :
  daemonAddress(""),
  daemonHost(""),
  daemonPort(0),
  help(false),
  logLevel(0),
  testnet(false),
  version(false) {
}

void SimpleWalletConfigurationOptions::initOptions(boost::program_options::options_description& optionsDescription) {
  command_line::add_arg(optionsDescription, arg_daemon_address);
  command_line::add_arg(optionsDescription, arg_daemon_host);
  command_line::add_arg(optionsDescription, arg_daemon_port);
  command_line::add_arg(optionsDescription, command_line::arg_help);
  command_line::add_arg(optionsDescription, arg_log_level);
  command_line::add_arg(optionsDescription, arg_testnet);
  command_line::add_arg(optionsDescription, command_line::arg_version); 
}

void SimpleWalletConfigurationOptions::init(const boost::program_options::variables_map& vm) {
  daemonAddress = command_line::get_arg(vm, arg_daemon_address);
  daemonHost = command_line::get_arg(vm, arg_daemon_host);
  daemonPort = command_line::get_arg(vm, arg_daemon_port);
  help = command_line::get_arg(vm, command_line::arg_help);
  logLevel = command_line::get_arg(vm, arg_log_level);
  testnet = command_line::get_arg(vm, arg_testnet);
  version = command_line::get_arg(vm, command_line::arg_version);
}

void SimpleWalletConfigurationOptions::printHelp(boost::program_options::options_description& optionsDescription)
{
  Common::Console::setTextColor(Common::Console::Color::BrightCyan);
  std::cout << '\n' << "Cash2 SimpleWallet version " << PROJECT_VERSION << '.' << PROJECT_VERSION_BUILD_NO << '\n' << '\n' << 
  "How To Run:" << '\n' << '\n' <<
  "Windows : simplewallet.exe" << '\n' <<
  "Linux and macOS : ./simplewallet" << '\n' << '\n' <<
  "To use a daemon address other than 127.0.0.1:12276 :" << '\n' << '\n' <<
  "Windows : simplewallet.exe --daemon-address=[host]:[port]" << '\n' <<
  "Linux and macOS : ./simplewallet --daemon-address=[host]:[port]" << '\n' << '\n' <<
  optionsDescription << std::endl;
  Common::Console::setTextColor(Common::Console::Color::Default);
}

void SimpleWalletConfigurationOptions::printVersion()
{
  Common::Console::setTextColor(Common::Console::Color::BrightCyan);
  std::cout << '\n' << "Cash2 SimpleWallet version" << PROJECT_VERSION << '.' << PROJECT_VERSION_BUILD_NO << std::endl;
  Common::Console::setTextColor(Common::Console::Color::Default);
}

} // end namespace CryptoNote

