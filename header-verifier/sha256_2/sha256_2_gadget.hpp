//
// Created by lylcx-mac on 2017/7/18.
//

#ifndef BOOTCAMP_ZKPSPV_SHA256_2_GADGET_HPP
#define BOOTCAMP_ZKPSPV_SHA256_2_GADGET_HPP

#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/data_structures/merkle_tree.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadgetlib1/gadgets/hashes/hash_io.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp"

namespace libsnark {

    template<typename FieldT>
    class sha256_2_function_check_gadget : public gadget<FieldT> {
    protected:
        std::shared_ptr<sha256_compression_function_gadget<FieldT>> gadget00;
        std::shared_ptr<sha256_compression_function_gadget<FieldT>> gadget01;
        std::shared_ptr<sha256_compression_function_gadget<FieldT>> gadget1;
        std::shared_ptr<multipacking_gadget<FieldT> > head_packer;
        std::shared_ptr<multipacking_gadget<FieldT> > hash_packer;
        std::shared_ptr<digest_variable<FieldT> > unpacked_head;
        std::shared_ptr<digest_variable<FieldT> > unpacked_hash;
        std::shared_ptr<digest_variable<FieldT> > midans1;
        std::shared_ptr<digest_variable<FieldT> > midans2;


    public:
        pb_variable<FieldT> ZERO;

        pb_variable_array<FieldT> packed_head;
        pb_variable_array<FieldT> packed_hash;


        sha256_2_function_check_gadget(protoboard<FieldT> &pb,
                                       const pb_variable_array<FieldT> &packed_head,
                                       const pb_variable_array<FieldT> &packed_hash,
                                       const std::string &annotation_prefix="") :
                gadget<FieldT>(pb, annotation_prefix),
                packed_head(packed_head),
                packed_hash(packed_hash) {
            assert(packed_head.size() == 20);
            assert(packed_hash.size() == 8);

            ZERO.allocate(pb, "zero");


            unpacked_head.reset(new digest_variable<FieldT>(pb, 20 * 32, FMT(annotation_prefix, " unpacked head v")));
            unpacked_hash.reset(new digest_variable<FieldT>(pb, 8 * 32, FMT(annotation_prefix, " unpacked hash v")));
            midans1.reset(new digest_variable<FieldT>(pb, 256, FMT(annotation_prefix, " midans1")));
            midans2.reset(new digest_variable<FieldT>(pb, 256, FMT(annotation_prefix, " midans2")));

            head_packer.reset(new multipacking_gadget<FieldT>(pb, unpacked_head->bits, packed_head, 32,
                                                              FMT(annotation_prefix, " head packer")));
            hash_packer.reset(new multipacking_gadget<FieldT>(pb, unpacked_hash->bits, packed_hash, 32,
                                                              FMT(annotation_prefix, " hash packer")));

            pb_variable_array<FieldT> chunk1(unpacked_head->bits.begin(), unpacked_head->bits.begin() + 512);
            byteReverse(chunk1);
            gadget00.reset(
                    new sha256_compression_function_gadget<FieldT>(pb, SHA256_default_IV<FieldT>(pb), chunk1, *midans1,
                                                                   FMT(this->annotation_prefix, " round00")));

            //std::cout << unpacked_head->bits.size() << std::endl;

            pb_variable_array<FieldT> chunk2(unpacked_head->bits.begin() + 512, unpacked_head->bits.end());
            byteReverse(chunk2);
            finalize(chunk2, 640, 320, ZERO);
            gadget01.reset(new sha256_compression_function_gadget<FieldT>(pb, midans1->bits, chunk2, *midans2,
                                                                          FMT(this->annotation_prefix, " round01")));

            pb_variable_array<FieldT> chunk3(midans2->bits.begin(), midans2->bits.end());
            finalize(chunk3, 256, 192, ZERO);

            pb_variable_array<FieldT> ans(unpacked_hash->bits.begin(), unpacked_hash->bits.end());
            byteReverse(ans);
            digest_variable<FieldT> final_ans(pb, 256, ans, ONE, "sha2 out digest");
            gadget1.reset(
                    new sha256_compression_function_gadget<FieldT>(pb, SHA256_default_IV<FieldT>(pb), chunk3, final_ans,
                                                                   FMT(this->annotation_prefix, " round01")));
        }

        void generate_r1cs_constraints() {
            (this->pb).add_r1cs_constraint(r1cs_constraint<FieldT>(1, ZERO, 0), "Force zero");
            unpacked_head->generate_r1cs_constraints();
            unpacked_hash->generate_r1cs_constraints();
            midans1->generate_r1cs_constraints();
            midans2->generate_r1cs_constraints();
            head_packer->generate_r1cs_constraints(false);
            hash_packer->generate_r1cs_constraints(false);

            gadget00->generate_r1cs_constraints();
            gadget01->generate_r1cs_constraints();
            gadget1->generate_r1cs_constraints();
        }

        void generate_r1cs_witness() {
            (this->pb).val(ZERO) = FieldT::zero();
            head_packer->generate_r1cs_witness_from_packed();

            gadget00->generate_r1cs_witness();
            gadget01->generate_r1cs_witness();
            gadget1->generate_r1cs_witness();

            hash_packer->generate_r1cs_witness_from_bits();
        }

        void byteReverse(pb_variable_array<FieldT> &vch) {
            assert(vch.size() % 32 == 0);
            typename pb_variable_array<FieldT>::iterator it;
            it = vch.begin();
            while (it != vch.end()) {
                std::reverse(it, it + 32);
                it += 32;
            }
            return;
        }

        void finalize(pb_variable_array<FieldT> &vch, uint64_t size, size_t padlen, pb_variable<FieldT> ZERO) {
            vch.emplace_back(ONE);
            for (size_t i = 0; i < padlen - 1; i++) {
                vch.emplace_back(ZERO);
            }
            for (size_t i = 0; i < 64; i++) {
                vch.emplace_back((size >> (63 - i) & 0x1) ? ONE : ZERO);
            }
            assert(vch.size() == 512);
            return;
        }
    };
}


#endif //BOOTCAMP_ZKPSPV_SHA256_2_GADGET_HPP
