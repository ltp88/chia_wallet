//
//  wrapper.cpp
//  Runner
//
//  Created by Phuong Lam on 5/9/21.
//

#include <stdint.h>
#include <stdio.h>
#include "bls.hpp"

#define PRIVATE_KEY_LEN 32
#define PUBLIC_KEY_LEN 48
#define SIGNATURE_LEN 96

using namespace std;

struct BlsKey {
    int8_t success;
    char* error;
    uint8_t* privateKey;       // 32 bytes
    uint8_t* publicKey;        // 48 bytes
    char* privateKeyStr;
    char* publicKeyStr;
};

struct ByteArray {
    uint8_t* data;
    unsigned long size;
};

void printKey(vector<uint8_t> key) {
    for (int i = 0; i < key.size(); i++) {
        cout << unsigned(key[i]) << ", ";
    }
    cout << endl;
}

vector<uint8_t> append(vector<uint8_t> a, vector<uint8_t> b) {
    
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
struct BlsKey generate_key() {
    std::vector<uint8_t> seed = {0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                                19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                                12, 62, 89, 110, 182, 9,   44, 20,  254, 22};
    
    bls::PrivateKey sk = bls::AugSchemeMPL().KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();
    
    cout << sk.Serialize().size() << endl;
    cout << pk.Serialize().size() << endl;
    
    struct BlsKey blsKey;
    uint8_t* privateKey = static_cast<uint8_t*>(malloc(32));
    uint8_t* publicKey = static_cast<uint8_t*>(malloc(48));
    
    vector<uint8_t> skB = sk.Serialize();
    vector<uint8_t> pkB = pk.Serialize();

    copy(skB.begin(), skB.end(), privateKey);
    copy(skB.begin(), pkB.end(), publicKey);
    
    blsKey.privateKey = privateKey;
    blsKey.publicKey = publicKey;
    
    blsKey.success = 0;
    
    printKey(sk.Serialize());
    cout << bls::Util::HexStr(sk.Serialize()) << endl;
    cout << bls::Util::HexStr(pk.Serialize()) << endl;
    
    return blsKey;
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
uint8_t* key_gen() {
    std::vector<uint8_t> seed = {0,  51, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                                19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                                12, 62, 89, 110, 182, 9,   44, 20,  254, 22};
    
    bls::PrivateKey sk = bls::AugSchemeMPL().KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();
    
    cout << bls::Util::HexStr(sk.Serialize()) << endl;
    cout << bls::Util::HexStr(pk.Serialize()) << endl;
    
    vector<uint8_t> data;
    data.push_back(0);
    
    vector<uint8_t> skB = sk.Serialize();
    vector<uint8_t> pkB = pk.Serialize();
    data.insert(data.end(), skB.begin(), skB.end());
    data.insert(data.end(), pkB.begin(), pkB.end());

    uint8_t* key = static_cast<uint8_t*>(malloc(81));
    copy(data.begin(), data.end(), key);
    return key;
}
//377091f0e728463bc2da7d546c53b9f6b81df4a1cc1ab5bf29c5908b7151a32d
extern "C" __attribute__((visibility("default"))) __attribute__((used))
struct BlsKey get_public_key(uint8_t* key) {
    bls::Bytes keyBytes = bls::Bytes(key, PRIVATE_KEY_LEN);
    bls::PrivateKey sk = bls::PrivateKey::FromBytes(keyBytes);
    bls::G1Element pk = sk.GetG1Element();
    
    struct BlsKey blsKey;
    blsKey.privateKey = sk.Serialize().data();
    blsKey.publicKey = pk.Serialize().data();
    return blsKey;
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
uint8_t* sign(uint8_t* key, uint8_t* message, size_t messageLen) {
    
    cout << bls::Util::HexStr(key, 32) << endl;
    cout << bls::Util::HexStr(key, 32) << endl;

    bls::Bytes keyBytes = bls::Bytes(key, PRIVATE_KEY_LEN);
    bls::PrivateKey sk = bls::PrivateKey::FromBytes(keyBytes);
    
    bls::G2Element signature = bls::AugSchemeMPL().Sign(sk, bls::Bytes(message, messageLen));
    vector<uint8_t> s = signature.Serialize();
    
    uint8_t* sign = static_cast<uint8_t*>(malloc(SIGNATURE_LEN));
    
    copy(s.begin(), s.end(), sign);
    
    return sign;
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
int8_t verify_key(uint8_t *key) {
    bls::Bytes keyBytes = bls::Bytes(key, PRIVATE_KEY_LEN);
    bls::PrivateKey sk = bls::PrivateKey::FromBytes(keyBytes);
    bls::G1Element pk = sk.GetG1Element();

    vector<uint8_t> message = {1, 2, 3, 4, 5};  // Message is passed in as a byte vector
    bls::G2Element signature = bls::AugSchemeMPL().Sign(sk, message);

    // Verify the signature
    if(bls::AugSchemeMPL().Verify(pk, message, signature)) {
        return 0;
    } else {
        return 1;
    }
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
uint8_t verify_signature(uint8_t *key, uint8_t *signature, uint8_t *message, size_t messageLen) {
    bls::G1Element pk = bls::G1Element().FromBytes(bls::Bytes(key, PUBLIC_KEY_LEN));
    bls::G2Element s = bls::G2Element().FromBytes(bls::Bytes(signature, SIGNATURE_LEN));
    bool success = bls::AugSchemeMPL().Verify(pk, bls::Bytes(message, messageLen), s);
    return success ? 0 : 1;
}
