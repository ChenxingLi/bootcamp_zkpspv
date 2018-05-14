# bootcamp_zkpspv

This is a project in IC3 boot campus in 2017. We are tring to use 'proof of carrying data' to reduce the space needed in Simplified Payment Verification (SPV).

Currently, the SPV client needs to store the block header of all the blocks. In this protocol, clients only need to store constant data, and the prover (full node) can make clients convince the correctness of transation using proof less than 1kB. The proof contains two parts: the first part is the same as original SPV protocol. Since the users doesn't store block header, the prover needs to prove the status of the block header in original SPV proof.

The prover needs to generate a proof for each block header sequentially. (But prover only needs to store the last proof.) According to our experiment, a 32-thread server can generate one proof in 3 second. So it will take about two weeks to generate a proof for the newest block and spend 3 second updating each new block. Fortunately, everyone can verify the proof quickly and use it directly. So we only need to run the heavy start-up once.

The code is uncompleted. Just use it for reference and learning. 

Collaborators for Idea and Code:

- Ahmed Kosba [@akosba](https://github.com/akosba)
- Haobi Ni [@FTRobbin](https://github.com/FTRobbin)
- Chenxing Li [@ChenxingLi](https://github.com/ChenxingLi)
- Xihu Zhang 
