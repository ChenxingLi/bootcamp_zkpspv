#ifndef HEADER_VERIFIER_GADGETS_TCC_
#define HEADER_VERIFIER_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"


namespace libsnark {

    template<typename FieldT>
    header_verifier_gadget<FieldT>::header_verifier_gadget(protoboard<FieldT> &pb,
                                                           const pb_variable_array<FieldT> &msg_input,
                                                           const pb_variable_array<FieldT> &local_input,
                                                           const pb_variable_array<FieldT> &msg_output,
                                                           const std::string &annotation_prefix) :
            gadget<FieldT>(pb, annotation_prefix),
            msg_input(msg_input),
            local_input(local_input),
            msg_output(msg_output) {
        timestamp_median.allocate(pb);
        pb_variable_array<FieldT> timestamp(msg_input.begin() + 8, msg_input.end());
        median11.reset(new median11_gadget<FieldT>(pb, timestamp, timestamp_median, annotation_prefix + " median11"));
        timecmp.reset(
                new unixtime_gadget<FieldT>(pb, timestamp_median, local_input[9], annotation_prefix + " timecmp"));
        this_hash.allocate(pb, 8);
        //SHA256x2.reset(new SHA256x2_gadget<FieldT>(pb, local_input, this_hash, annotation_prefix + " SHA256x2"));
        diffcmp.reset(new difficulty_comparison_gadget<FieldT>(pb, this_hash, local_input[10]));
    }

    template<typename FieldT>
    void generate_r1cs_equal_constraint(protoboard<FieldT> &pb, const pb_linear_combination<FieldT> &A,
                                        const pb_linear_combination<FieldT> &B) {
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, A - B, 0));

    }

    template<typename FieldT>
    void header_verifier_gadget<FieldT>::generate_r1cs_constraints() {
        //1. Compare to previous hash
        //TODO: Optimization: pack the equality test - no much use
        for (int i = 0; i < 8; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, local_input[1 + i], msg_input[i]);
        }
        //2. Compare timestamp
        median11->generate_r1cs_constraints();
        timecmp->generate_r1cs_constraints();

        //3. Compare hash
        //3.1 Compute hash
        //SHA256x2->generate_r1cs_constraints();
        //3.2 Compare with difficulty
        diffcmp->generate_r1cs_constraints();
        //4. Get output
        for (int i = 0; i < 8; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[i], this_hash[i]);
        }
        generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[8], local_input[17]);
        for (int i = 1; i < 11; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[8 + i], msg_output[i + 7]);
        }
    }

    template<typename FieldT>
    void header_verifier_gadget<FieldT>::generate_r1cs_witness() {
        median11->generate_r1cs_witness();
        timecmp->generate_r1cs_witness();
        //SHA256x2->generate_r1cs_witness();
        diffcmp->generate_r1cs_witness();
        for (int i = 0; i < 8; ++i) {
            this->pb.val(msg_output[i]) = this->pb.val(this_hash[i]);
        }
        for (int i = 0; i < 11; ++i) {
            this->pb.val(msg_output[8 + i]) = i ? this->pb.val(timestamp[i + 7]) : this->pb.val(local_input[17]);
        }
    }


} // libsnark
#endif // HEADER_VERIFIER_GADGETS_TCC_
