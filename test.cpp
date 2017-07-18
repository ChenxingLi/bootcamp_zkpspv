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

//    BlockHeader header(
//            "10000020670b600f6deb63be236764dd013fdca071f2be230fb10d010000000000000000d77b83ae14bfe06f14bb01e5aaaa5f29679bc7cdbd93a3de62070cf8810dd6047f1c6d59dc5d011861176a68");
    BlockHeader header("10000020670b600f6deb63be236764dd013fdca071f2be230fb10d010000000000000000d77b83ae14bfe06f14bb01e5aaaa5f29679bc7cdbd93a3de62070cf8810dd6047f1c6d59dc5d011861176a68");
    BlockHash out_hash("0000000000000000007df6d6851fd8b104b02ed9173cb14202aee5fa66c96443", false);
    BlockHash in_hash("0000000000000000010db10f23bef271a0dc3f01dd646723be63eb6d0f600b67", false);
//    BlockHash test(
//            "18241824182418241824182418241824182418241824182418241824182418241824182418241824182418241824182418241824182418241824182418241824");

    BlockHash test1("10000020670b600f6deb63be236764dd013fdca071f2be230fb10d0100000000");
    BlockHash test2("00000000d77b83ae14bfe06f14bb01e5aaaa5f29679bc7cdbd93a3de62070cf8");

    CSHA256 sha2;
    uint256 ans;
    sha2.Write(test1.begin(), 32);
    sha2.Write(test2.begin(), 32);
    sha2.FinalizeNoPadding(ans.begin());
    std::cout << ans.GetHexInv() << std::endl;
    std::cout<< header.getFirstHash().GetHexInv() << std::endl;
    std::cout<< header.getHash().GetHexInv() << std::endl;


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

int main(int argc, char *argv[]) {
    packcheck();
    return 0;
}