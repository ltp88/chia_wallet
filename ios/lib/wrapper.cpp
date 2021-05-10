//
//  wrapper.cpp
//  Runner
//
//  Created by Phuong Lam on 5/9/21.
//

#include <stdint.h>
#include "bls.hpp"

struct BlsKey {
    uint8_t* private_key;       // 32 bytes
    uint8_t* public_key;        // 48 bytes
};

//struct BlsKey create_key(

extern "C" __attribute__((visibility("default"))) __attribute__((used))
struct BlsKey generate_key() {
    std::vector<uint8_t> seed = {0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                                19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                                12, 62, 89, 110, 182, 9,   44, 20,  254, 22};

    bls::PrivateKey sk = bls::AugSchemeMPL().KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();
    struct BlsKey bls;
    bls.private_key = sk.Serialize().data();
    bls.public_key = pk.Serialize().data();
    return bls;
}

