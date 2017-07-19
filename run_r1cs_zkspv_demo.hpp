//
// Created by lylcx-mac on 2017/7/18.
//

#ifndef BOOTCAMP_ZKPSPV_RUN_R1CS_ZKSPV_DEMO_HPP
#define BOOTCAMP_ZKPSPV_RUN_R1CS_ZKSPV_DEMO_HPP

#include <zk_proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>
#include "common/profiling.hpp"
#include "zkspv_cp.hpp"

using std::vector;
using std::string;
using std::shared_ptr;
using namespace libsnark;

template<typename PCD_ppT>
bool run_r1cs_zkspv_demo(vector<string> &sheader) {
    enter_block("Call to run_r1cs_sp_ppzkpcd_tally_example");

    typedef Fr<typename PCD_ppT::curve_A_pp> FieldT;
    bool all_accept = true;

    TimeStamp timeStamp;

    enter_block("Prepare messages");
    size_t node_size = sheader.size();

    vector<shared_ptr<r1cs_pcd_local_data<FieldT>>> vec_ld(node_size + 1);
    vector<shared_ptr<r1cs_pcd_message<FieldT>>> vec_msg(node_size + 1);
    vector<r1cs_sp_ppzkpcd_proof<PCD_ppT >> proofs(node_size + 1);

    vec_msg[0].reset(new zkspv_pcd_message<FieldT>(0, BlockHeader(sheader[0]).getPrevHash(), uint256(), timeStamp));

    for (size_t i = 1; i <= node_size; i++) {
        BlockHeader header = BlockHeader(sheader[i-1]);
        timeStamp.update(header.getTimeStamp());
        vec_ld[i].reset(new zkspv_pcd_local_data<FieldT>(header));
        vec_msg[i].reset(new zkspv_pcd_message<FieldT>(1, header.getHash(), uint256(), timeStamp));
    }
    leave_block("Prepare messages");


    enter_block("Generate compliance predicate");
    const size_t type = 1;
    const size_t capacity = FieldT::capacity();
    zkspv_cp_handler<FieldT> zkspv(type, capacity);
    zkspv.generate_r1cs_constraints();
    r1cs_pcd_compliance_predicate<FieldT> zkspv_cp = zkspv.get_compliance_predicate();
    leave_block("Generate compliance predicate");

    print_header("R1CS ppzkPCD Generator");
    r1cs_sp_ppzkpcd_keypair<PCD_ppT> keypair = r1cs_sp_ppzkpcd_generator<PCD_ppT>(zkspv_cp);

    print_header("Process verification key");
    r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> pvk = r1cs_sp_ppzkpcd_process_vk<PCD_ppT>(keypair.vk);


    for (size_t i = 1; i <= node_size; i++) {

        zkspv.generate_r1cs_witness(vec_msg[i - 1], vec_msg[i], vec_ld[i]);

        const r1cs_pcd_compliance_predicate_primary_input<FieldT> tally_primary_input(vec_msg[i]);
        const r1cs_pcd_compliance_predicate_auxiliary_input<FieldT> tally_auxiliary_input(
                vector<std::shared_ptr<r1cs_pcd_message<FieldT >>>(1, vec_msg[i-1]),
                vec_ld[i],
                zkspv.get_witness());

        print_header("R1CS ppzkPCD Prover");
        r1cs_sp_ppzkpcd_proof<PCD_ppT> proof;
        proof = r1cs_sp_ppzkpcd_prover<PCD_ppT>(keypair.pk,
                                                tally_primary_input,
                                                tally_auxiliary_input,
                                                vector<r1cs_sp_ppzkpcd_proof<PCD_ppT >>(1, proofs[i - 1]));

        proofs[i] = proof;


        print_header("R1CS ppzkPCD Verifier");
        const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> pcd_verifier_input(vec_msg[i]);
        const bool ans = r1cs_sp_ppzkpcd_verifier<PCD_ppT>(keypair.vk, pcd_verifier_input, proof);

        print_header("R1CS ppzkPCD Online Verifier");
        const bool ans2 = r1cs_sp_ppzkpcd_online_verifier<PCD_ppT>(pvk, pcd_verifier_input, proof);
        assert(ans == ans2);

        all_accept = all_accept && ans;

        assert(all_accept);

        printf("Current node = %zu. Current proof verifies = %s\n", i, ans ? "YES" : "NO");
        printf("\n\n\n ================================================================================\n\n\n");
    }

    leave_block("Call to run_r1cs_sp_ppzkpcd_tally_example");

    return all_accept;
}

#endif //BOOTCAMP_ZKPSPV_RUN_R1CS_ZKSPV_DEMO_HPP
