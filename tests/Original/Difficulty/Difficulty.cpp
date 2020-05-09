// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Difficulty.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"

using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Wrong arguments" << endl;
        return 1;
    }
    Logging::ConsoleLogger logger;
    CryptoNote::CurrencyBuilder currencyBuilder(logger);
    currencyBuilder.difficultyTarget(9);
    currencyBuilder.difficultyWindow(90);
    currencyBuilder.difficultyCut(40);
    currencyBuilder.difficultyLag(15);
    CryptoNote::Currency currency = currencyBuilder.currency();
    vector<uint64_t> timestamps, cumulative_difficulties;
    fstream data(argv[1], fstream::in);
    data.exceptions(fstream::badbit);
    data.clear(data.rdstate());
    uint64_t timestamp, difficulty, cumulative_difficulty = 0;
    size_t n = 0;
    while (data >> timestamp >> difficulty) {
        size_t begin, end;
        if (n < currency.difficultyWindow() + currency.difficultyLag()) {
            begin = 0;
            end = min(n, currency.difficultyWindow());
        } else {
            end = n - currency.difficultyLag();
            begin = end - currency.difficultyWindow();
        }
        uint64_t res = currency.nextDifficulty1(
            vector<uint64_t>(timestamps.begin() + begin, timestamps.begin() + end),
            vector<uint64_t>(cumulative_difficulties.begin() + begin, cumulative_difficulties.begin() + end));
        if (res != difficulty) {
            cerr << "Wrong difficulty for block " << n << endl
                << "Expected: " << difficulty << endl
                << "Found: " << res << endl;


            // // below is used to print out the correct values to the file "data.txt"
            

            // data.close();

            // string x;
            // ifstream file ( "/media/sf_Shared/cryptonote/tests/Difficulty/data.txt" );
            // ofstream ofile ( "/media/sf_Shared/cryptonote/tests/Difficulty/data2.txt" );

            // size_t count = 0;

            // while (!file.eof())
            // {
              // getline(file, x);

              // if (count == n)
              // {
                // ofile << timestamp << " " << res << endl;
              // }
              // else
              // {
                // ofile << x << endl;
              // }

              // count++;
            // }

            // file.close();
            // ofile.close();

            // remove( "/media/sf_Shared/cryptonote/tests/Difficulty/data.txt" );

            // char oldname[] = "/media/sf_Shared/cryptonote/tests/Difficulty/data2.txt";
            // char newname[] = "/media/sf_Shared/cryptonote/tests/Difficulty/data.txt";
            // rename( oldname , newname );

            

            return 1;
        }
        timestamps.push_back(timestamp);
        cumulative_difficulties.push_back(cumulative_difficulty += difficulty);
        ++n;
    }
    if (!data.eof()) {
        data.clear(fstream::badbit);
    }
    return 0;
}
