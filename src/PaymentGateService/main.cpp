// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <memory>
#include <string.h>
#include <thread>

#include "Logging/LoggerManager.h"
#include "PaymentGateService.h"
#include "version.h"

int main(int argc, char** argv) {

  PaymentGateService paymentGateService; 

  try
  {
    if (!paymentGateService.init(argc, argv)) {
      return 0;
    }

    Logging::LoggerRef logger(paymentGateService.getLogger(), "main");
    logger(Logging::INFO) << "PaymentService " << " v" << PROJECT_VERSION_LONG;

    const PaymentService::WalletdConfigurationOptions& config = paymentGateService.getConfig();

    if (config.generateNewContainer) {
      System::Dispatcher d;
      generateNewWallet(paymentGateService.getCurrency(), paymentGateService.getWalletConfig(), paymentGateService.getLogger(), d);
      return 0;
    }

    paymentGateService.run();

  }
  catch (std::exception& ex)
  {
    std::cerr << "Error: " << ex.what() << std::endl;
    return 1;
  }

  return 0;
}
