#ifndef HEADER_VERIFIER_GADGETS_TCC_
#define HEADER_VERIFIER_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"


namespace libsnark {

    template<typename FieldT>
    header_verifier_gadget<FieldT>::header_verifier_gadget(protoboard <FieldT> &pb,
                                                           const pb_variable_array <FieldT> &msg_input,
                                                           const pb_variable_array <FieldT> &local_input,
                                                           const pb_variable_array <FieldT> &msg_output,
                                                           const std::string &annotation_prefix) :
            gadget<FieldT>(pb, annotation_prefix),
            msg_input(msg_input),
            local_input(local_input),
            msg_output(msg_output) {
        timestamp_median.allocate(pb);
        pb_variable_array <FieldT> timestamp(msg_input.begin() + 8, msg_input.begin() + 19);
        median11.reset(
                new median11_gadget<FieldT>(pb, timestamp, timestamp_median, FMT(annotation_prefix, " median11")));
        timecmp.reset(
                new unixtime_gadget<FieldT>(pb, timestamp_median, local_input[17], FMT(annotation_prefix, " timecmp")));
        this_hash.allocate(pb, 8);
        SHA256x2.reset(new sha256_2_function_check_gadget<FieldT>(pb, local_input, this_hash, annotation_prefix + " SHA256x2"));
        diffcmp.reset(new difficulty_comparison_gadget<FieldT>(pb, this_hash, local_input[18]));

		pb_variable_array<FieldT> last_root(msg_input.begin() + 19, msg_input.begin() + 27);
		this_addr.allocate(pb);
		this_root.allocate(pb, 8);
		merkle.reset(new merkle_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >(pb, msg_input[27], this_addr, last_root, this_root, local_input));
    }

    template<typename FieldT>
    void generate_r1cs_equal_constraint(protoboard <FieldT> &pb, const pb_linear_combination <FieldT> &A,
                                        const pb_linear_combination <FieldT> &B) {
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
        SHA256x2->generate_r1cs_constraints();
        //3.2 Compare with difficulty
        diffcmp->generate_r1cs_constraints();
		//4. merkle
		merkle->generate_r1cs_constraints();
        //5. Get output
        for (int i = 0; i < 8; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[i], this_hash[i]);
        }
        generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[8], local_input[17]);
        for (int i = 1; i < 11; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[8 + i], msg_input[i + 7]);
        }
		for (int i = 0; i < 8; ++i) {
            generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[19 + i], this_root[i]);
		}
		generate_r1cs_equal_constraint<FieldT>(this->pb, msg_output[27], this_addr);
    }

    template<typename FieldT>
    void header_verifier_gadget<FieldT>::generate_r1cs_witness() {
        median11->generate_r1cs_witness();
        timecmp->generate_r1cs_witness();
        SHA256x2->generate_r1cs_witness();
        diffcmp->generate_r1cs_witness();
		merkle->generate_r1cs_witness();
        for (int i = 0; i < 8; ++i) {
            this->pb.val(msg_output[i]) = this->pb.val(this_hash[i]);
        }
        for (int i = 0; i < 11; ++i) {
            this->pb.val(msg_output[8 + i]) = i ? this->pb.val(msg_input[i + 7]) : this->pb.val(local_input[17]);
        }
		for (int i = 0; i < 8; ++i) {
            this->pb.val(msg_output[19 + i]) = this->pb.val(this_root[i]);
		}
		this->pb.val(msg_output[27]) = this->pb.val(this_addr);

		/*
		for (int i = 0; i < 28; ++i) {
			std::cout << this->pb.val(msg_output[i]).as_ulong() << std::endl;
		}
		*/
    }


} // libsnark
#endif // HEADER_VERIFIER_GADGETS_TCC_
