//
// Created by lylcx-mac on 2017/7/17.
//

#include "sha256.h"
#include "tool.h"
#include <iostream>
#include <string>
#include <cstring>

#include <common/default_types/r1cs_ppzkpcd_pp.hpp>
#include <zk_proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>
#include "zkspv_cp.hpp"
#include "run_r1cs_zkspv_demo.hpp"

using std::string;

using namespace libsnark;

void hashcheck() {
    CSHA256 sha256;
    string headerHash = "020000007ef055e1674d2e6551dba41cd214debbee34aeb544c7ec670000000000000000d3998963f80c5bab43fe8c26228e98d030edf4dcbe48a666f5c39e2d7a885c9102c86d536c890019593a470d";
    BlockHeader header(headerHash);
    uint256 hash = header.getHash();

    std::cout << hash.GetHexInv() << std::endl;

}


void packcheck() {
    /****** Set up********/

    typedef default_r1cs_ppzkpcd_pp PCD_ppT;

    start_profiling();
    PCD_ppT::init_public_params();
    typedef Fr<typename PCD_ppT::curve_A_pp> FieldT;

    const size_t type = 1;
    const size_t capacity = FieldT::capacity();

    /****** Build Circuit ********/

    zkspv_cp_handler<FieldT> zkspv(type, capacity);
    zkspv.generate_r1cs_constraints();

    TimeStamp timestamp;

    BlockHeader header(
            "10000020670b600f6deb63be236764dd013fdca071f2be230fb10d010000000000000000d77b83ae14bfe06f14bb01e5aaaa5f29679bc7cdbd93a3de62070cf8810dd6047f1c6d59dc5d011861176a68");
    BlockHash out_hash("0000000000000000007df6d6851fd8b104b02ed9173cb14202aee5fa66c96443", false);
    BlockHash in_hash("0000000000000000010db10f23bef271a0dc3f01dd646723be63eb6d0f600b67", false);

    assert(header.getHash() == out_hash);
    assert(header.getPrevHash() == in_hash);

    std::cout << header.getFirstHash().GetHexInv() << std::endl;
    std::cout << header.getHash().GetHexInv() << std::endl;


    std::shared_ptr<r1cs_pcd_message<FieldT> > incoming_message;
    incoming_message.reset(new zkspv_pcd_message<FieldT>(1, in_hash, uint256(), timestamp));

    timestamp.update(header.getTimeStamp());
    std::shared_ptr<r1cs_pcd_message<FieldT> > outcoming_message;
    outcoming_message.reset(new zkspv_pcd_message<FieldT>(1, out_hash, uint256(), timestamp));

    std::shared_ptr<r1cs_pcd_local_data<FieldT> > local_data;
    local_data.reset(new zkspv_pcd_local_data<FieldT>(header));
    zkspv.generate_r1cs_witness(incoming_message, outcoming_message, local_data);

    zkspv.is_satisfied();

    std::cout << "Test Passed!" << std::endl;
}

void testdemo(){
    typedef default_r1cs_ppzkpcd_pp PCD_ppT;

    start_profiling();
    PCD_ppT::init_public_params();

    vector<string> sheaders;
    sheaders.push_back("020000208d0c715f0a32cca0f14a739114209fd90686dc481a2ece000000000000000000895fe03d7fa2b4cc8f8df0860396eb1ae6a4f8659cd5dacc1cfc4bd5d3b3cdf48c0f6d59dc5d01182189e871");
    sheaders.push_back("100000202313f27b0b91489bcddca448b4c621a04366a45e3154bd0000000000000000008799e8b70cd66479f51cdc2e298fb01fc6408cd9cd6a6a90077b059da7f153821a116d59dc5d011830976782");
    sheaders.push_back("10000020eda1fb44849d9a371bf345c4c0d98ef5f0064efe7610550000000000000000009fad331c30ac1a0639adf9ff78b953cc2f6e9956ef1d55570e6db879bac7e2fb7a136d59dc5d011897855309");

    assert(BlockHeader(sheaders[1]).getPrevHash()==BlockHeader(sheaders[0]).getHash());

    const bool bit = run_r1cs_zkspv_demo<PCD_ppT>(sheaders);
    assert(bit);
}

int main(int argc, char *argv[]) {
    testdemo();
    return 0;
}
