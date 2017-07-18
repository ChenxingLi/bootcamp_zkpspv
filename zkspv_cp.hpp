//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_ZKSPV_CP_HPP
#define BOOTCAMP_ZKPSPV_ZKSPV_CP_HPP

#include "zkspv_lm.hpp"

namespace libsnark {
    template<typename FieldT>
    class zkspv_cp_handler : public compliance_predicate_handler<FieldT, protoboard<FieldT> > {
    public:
        typedef compliance_predicate_handler<FieldT, protoboard<FieldT> > base_handler;

        std::shared_ptr<zkspv_message_packer<FieldT> > msgpack_in;
        std::shared_ptr<zkspv_message_packer<FieldT> > msgpack_out;


        zkspv_cp_handler(const size_t type,
                                                   const size_t capacity,
                                                   const size_t max_arity = 1,
                                                   const bool relies_on_same_type_inputs = false,
                                                   const std::set<size_t> accepted_input_types = std::set<size_t>()) :
                compliance_predicate_handler<FieldT, protoboard<FieldT> >(protoboard<FieldT>(),
                                                                          type * 100,
                                                                          type,
                                                                          max_arity,
                                                                          relies_on_same_type_inputs
                ) {
            this->outgoing_message.reset(
                    new zkspv_pcd_message_variable<FieldT>(this->pb, capacity, "outgoing_message"));
            this->arity.allocate(this->pb, "arity");

            for (size_t i = 0; i < max_arity; ++i) {
                this->incoming_messages[i].reset(new zkspv_pcd_message_variable<FieldT>(this->pb, capacity,
                                                                                        FMT("", "incoming_messages_%zu",
                                                                                            i)));
            }

            this->local_data.reset(new zkspv_pcd_local_data_variable<FieldT>(this->pb, "local_data"));

            this->msgpack_in.reset(new zkspv_message_packer<FieldT>(this->pb,
                                                            std::dynamic_pointer_cast<zkspv_pcd_message_variable<FieldT> >(
                                                                    this->incoming_messages[0])->packed_message,
                                                            capacity, "in_message"));
            this->msgpack_out.reset(new zkspv_message_packer<FieldT>(this->pb,
                                                             std::dynamic_pointer_cast<zkspv_pcd_message_variable<FieldT> >(
                                                                     this->outgoing_message)->packed_message, capacity,
                                                             "out_message"));
        }

        void generate_r1cs_constraints() {
            this->msgpack_in->generate_r1cs_constraints();
            this->msgpack_out->generate_r1cs_constraints();
        }

        void generate_r1cs_witness(const std::shared_ptr<r1cs_pcd_message<FieldT> > &incoming_message,
                                   const std::shared_ptr<r1cs_pcd_message<FieldT> > &outcoming_message,
                                   const std::shared_ptr<r1cs_pcd_local_data<FieldT> > &local_data) {

            std::vector<std::shared_ptr<r1cs_pcd_message<FieldT> > > incoming_messages(1, incoming_message);
            base_handler::generate_r1cs_witness(incoming_messages, local_data);
            this->outgoing_message->generate_r1cs_witness(outcoming_message);
            this->msgpack_in->generate_r1cs_witness();
            this->msgpack_out->generate_r1cs_witness();
        }

        std::shared_ptr<r1cs_pcd_message<FieldT> > get_base_case_message() const;

        void is_satisfied() {
            assert(this->pb.is_satisfied());
        }
    };
}
#endif //BOOTCAMP_ZKPSPV_ZKSPV_CP_HPP
