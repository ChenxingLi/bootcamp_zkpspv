//
// Created by lylcx-mac on 2017/7/17.
//

#include "sha256.h"
#include "tool.h"
#include <iostream>

int main() {
    CSHA256 sha256;
    uint256 ans;
    unsigned char data[1];
    data[0] = '1';
    sha256.Write(data, 1);
    sha256.Finalize(ans.begin());
    std::cout<< ans.GetHexStr() <<std::endl;

    return 0;
}