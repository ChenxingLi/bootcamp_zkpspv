//
// Created by lylcx-mac on 2017/7/17.
//

#include "sha256.h"
#include "tool.h"
#include <iostream>
#include "common/default_types/r1cs_ppzkpcd_pp.hpp"
#include "algebra/curves/public_params.hpp"

int main() {
    CSHA256 sha256;
    uint256 ans;
    unsigned char data[1];
    data[0] = '@';
    sha256.Write(data, 1);
    sha256.Finalize(ans.begin());
    std::cout<< ans.GetHexStr() <<std::endl;


    std::cout << libsnark::Fr<typename libsnark::default_r1cs_ppzkpcd_pp::curve_A_pp>::capacity()<<std::endl;
    return 0;
}