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

template<typename PCD_ppT>
int run_r1cs_zkspv_demo(vector<string>& sheader){
    enter_block("Call to run_r1cs_sp_ppzkpcd_tally_example");

    typedef Fr<typename PCD_ppT::curve_A_pp> FieldT;
    bool all_accept = true;

    TimeStamp timeStamp;


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

    size_t length = sheader.size();

    for (size_t cur_idx = 0; cur_idx < length; cur_idx ++) {
        BlockHeader header = BlockHeader(sheader[cur_idx]);
        BlockHash prevHash = header.getPrevHash();
        BlockHash hash = header.getHash();


        std::shared_ptr<r1cs_pcd_local_data<FieldT> > ld;
        ld.reset(new zkspv_pcd_local_data<FieldT>(header));
        zkspv.generate_r1cs_witness(msgs, ld);

        const r1cs_pcd_compliance_predicate_primary_input<FieldT> tally_primary_input(tally.get_outgoing_message());
        const r1cs_pcd_compliance_predicate_auxiliary_input<FieldT> tally_auxiliary_input(msgs, ld,
                                                                                          tally.get_witness());

        print_header("R1CS ppzkPCD Prover");
        r1cs_sp_ppzkpcd_proof<PCD_ppT> proof = r1cs_sp_ppzkpcd_prover<PCD_ppT>(keypair.pk, tally_primary_input,
                                                                               tally_auxiliary_input, proofs);

        if (test_serialization) {
            enter_block("Test serialization of proof");
            proof = reserialize<r1cs_sp_ppzkpcd_proof<PCD_ppT> >(proof);
            leave_block("Test serialization of proof");
        }

        tree_proofs[cur_idx] = proof;
        tree_messages[cur_idx] = tally.get_outgoing_message();

        print_header("R1CS ppzkPCD Verifier");
        const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> pcd_verifier_input(tree_messages[cur_idx]);
        const bool ans = r1cs_sp_ppzkpcd_verifier<PCD_ppT>(keypair.vk, pcd_verifier_input, tree_proofs[cur_idx]);

        print_header("R1CS ppzkPCD Online Verifier");
        const bool ans2 = r1cs_sp_ppzkpcd_online_verifier<PCD_ppT>(pvk, pcd_verifier_input, tree_proofs[cur_idx]);
        assert(ans == ans2);

        all_accept = all_accept && ans;

        printf("\n");
        for (size_t i = 0; i < arity; ++i) {
            printf("Message %zu was:\n", i);
            msgs[i]->print();
        }

        printf("Summand at this node:\n%zu\n", tree_elems[cur_idx]);
        printf("Outgoing message is:\n");
        tree_messages[cur_idx]->print();
        printf("\n");
        printf("Current node = %zu. Current proof verifies = %s\n", cur_idx, ans ? "YES" : "NO");
        printf("\n\n\n ================================================================================\n\n\n");
    }

    leave_block("Call to run_r1cs_sp_ppzkpcd_tally_example");

}

#endif //BOOTCAMP_ZKPSPV_RUN_R1CS_ZKSPV_DEMO_HPP
