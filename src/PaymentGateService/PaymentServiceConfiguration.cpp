// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PaymentServiceConfiguration.h"

#include <iostream>
#include <algorithm>
#include <boost/program_options.hpp>

#include "Logging/ILogger.h"
#include "CryptoNoteConfig.h"

namespace po = boost::program_options;

namespace PaymentService {

Configuration::Configuration() {
  generateNewContainer = false;
  daemonize = false;
  registerService = false;
  unregisterService = false;
  logFile = "payment_gate.log";
  testnet = false;
  printAddresses = false;
  logLevel = Logging::INFO;
  bindAddress = "";
  bindPort = 0;
  rpcConfigurationPassword = "";
}

void Configuration::initOptions(boost::program_options::options_description& desc) {
  desc.add_options()
      ("address", "print wallet addresses and exit")
      ("bind-address", po::value<std::string>()->default_value("127.0.0.1"), "payment service bind address")
      ("bind-port", po::value<uint16_t>()->default_value(CryptoNote::WALLETD_DEFAULT_PORT), "payment service bind port")
      ("container-file,w", po::value<std::string>(), "container file")
      ("container-password,p", po::value<std::string>(), "container password")
      ("daemon,d", "run as daemon in Unix or as service in Windows")
      ("generate-container,g", "generate new container file with one wallet and exit")
      ("log-file,l", po::value<std::string>(), "log file")
      ("log-level", po::value<size_t>(), "log level")
#ifdef _WIN32
      ("register-service", "register service and exit (Windows only)")
      ("unregister-service", "unregister service and exit (Windows only)")
#endif
      ("rpc-password", po::value<std::string>(), "Specify a password for access to the wallet RPC server.")
      ("server-root", po::value<std::string>(), "server root. The service will use it as working directory. Don't set it if don't want to change it")
      ("spend-private-key", po::value<std::string>(), "Specify the spend private key that you want your first wallet file to have")
      ("view-private-key", po::value<std::string>(), "Specify the view private key that you want your wallet container");
}

void Configuration::init(const boost::program_options::variables_map& options) {
  if (options.count("daemon") != 0) {
    daemonize = true;
  }

  if (options.count("register-service") != 0) {
    registerService = true;
  }

  if (options.count("unregister-service") != 0) {
    unregisterService = true;
  }

  if (registerService && unregisterService) {
    throw ConfigurationError("It's impossible to use both \"register-service\" and \"unregister-service\" at the same time");
  }

  if (options["testnet"].as<bool>()) {
    testnet = true;
  }

  if (options.count("log-file") != 0) {
    logFile = options["log-file"].as<std::string>();
  }

  if (options.count("log-level") != 0) {
    logLevel = options["log-level"].as<size_t>();
    if (logLevel > Logging::TRACE) {
      std::string error = "log-level option must be in " + std::to_string(Logging::FATAL) +  ".." + std::to_string(Logging::TRACE) + " interval";
      throw ConfigurationError(error.c_str());
    }
  }

  if (options.count("server-root") != 0) {
    serverRoot = options["server-root"].as<std::string>();
  }

  if (options.count("bind-address") != 0 && (!options["bind-address"].defaulted() || bindAddress.empty())) {
    bindAddress = options["bind-address"].as<std::string>();
  }

  if (options.count("bind-port") != 0 && (!options["bind-port"].defaulted() || bindPort == 0)) {
    bindPort = options["bind-port"].as<uint16_t>();
  }

  if (options.count("container-file") != 0) {
    containerFile = options["container-file"].as<std::string>();
  }

  if (options.count("container-password") != 0) {
    containerPassword = options["container-password"].as<std::string>();
  }

  if (options.count("generate-container") != 0) {
    generateNewContainer = true;
  }

  if (options.count("spend-private-key") != 0) {
    if (!generateNewContainer) {
      throw ConfigurationError("generate-container parameter is required");
    }

    spendPrivateKey = options["spend-private-key"].as<std::string>();
  }

  if (options.count("view-private-key") != 0) {
    if (!generateNewContainer) {
      throw ConfigurationError("generate-container parameter is required");
    }

    viewPrivateKey = options["view-private-key"].as<std::string>();
  }

  if((!spendPrivateKey.empty() && viewPrivateKey.empty()) || (spendPrivateKey.empty() && !viewPrivateKey.empty()))
  {
    throw ConfigurationError("Must specify both spend private key and view private key to restore wallet");
  }

  if (options.count("address") != 0) {
    printAddresses = true;
  }

  if (!registerService && !unregisterService) {
    if (containerFile.empty() || containerPassword.empty()) {
      throw ConfigurationError("Both container-file and container-password parameters are required");
    }
  }

  if (!(options.count("rpc-password") == 0)) {
    rpcConfigurationPassword = options["rpc-password"].as<std::string>();
  }

}

} //namespace PaymentService
