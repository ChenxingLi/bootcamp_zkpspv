//
// Created by lylcx-mac on 2017/7/17.
//

#include "sha256.h"
#include "tool.h"
#include <iostream>

#include <common/default_types/r1cs_ppzkpcd_pp.hpp>
#include <zk_proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>
#include "zkspv_cp.hpp"


using namespace libsnark;

void hashcheck(){
    CSHA256 sha256;
    base_blob<640> header;
    uint256 ans;

    header.SetHexInv("020000007ef055e1674d2e6551dba41cd214debbee34aeb544c7ec670000000000000000d3998963f80c5bab43fe8c26228e98d030edf4dcbe48a666f5c39e2d7a885c9102c86d536c890019593a470d");
    std::cout << int(*header.begin()) <<std::endl;
    std::cout << int(*(header.begin()+1)) <<std::endl;
    sha256.Write(header.begin(),80);
    sha256.Finalize(ans.begin());
    sha256.Reset();

    sha256.Write(ans.begin(),32);
    sha256.Finalize(ans.begin());
    std::cout << int(*ans.begin()) <<std::endl;

    std::cout<< ans.GetHexStr() <<std::endl;
}

int main(int argc, char* argv[])
{
    typedef default_r1cs_ppzkpcd_pp PCD_ppT;

    start_profiling();
    PCD_ppT::init_public_params();


    typedef Fr<typename PCD_ppT::curve_A_pp> FieldT;


    const size_t type = 1;
    const size_t capacity = FieldT::capacity();

    zkspv_cp_handler<FieldT> zkspv(type, capacity);
    zkspv.generate_r1cs_constraints();

    std::vector<uint32_t> timestamp(11,0xd);

    std::shared_ptr<r1cs_pcd_message<FieldT> > incoming_message;
    incoming_message.reset(new zkspv_pcd_message<FieldT>(1,uint256(), uint256(), timestamp));
    std::shared_ptr<r1cs_pcd_message<FieldT> > outcoming_message;
    outcoming_message.reset(new zkspv_pcd_message<FieldT>(1,uint256(), uint256(), timestamp));
    std::shared_ptr<r1cs_pcd_local_data<FieldT> > local_data;
    local_data.reset(new zkspv_pcd_local_data<FieldT>(BlockHeader()));
    zkspv.generate_r1cs_witness(incoming_message, outcoming_message, local_data);

    zkspv.is_satisfied();

    std::cout<< "Test Passed!" <<std::endl;

    return 0;
}