/* Copyright © 2020 Dirk-Willem van Gulik. All rights reserved.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 This requires https://github.com/kokke/tiny-AES-c.git

 */

#include <stdio.h>
#include <unistd.h>
#include <strings.h>

#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>


#include <assert.h>
#include <strings.h>
#include <stdlib.h>

// #define TINY

#ifdef TINY
// https://github.com/kokke/tiny-AES-c.git - AES128 is de default
// AES256 needs to be set in AES256
#include "tiny-AES-c/aes.h"
#else
#include <openssl/evp.h>
#endif

#define SKT_LEN (32)
#define SKT_BITLEN (SKT_LEN * 8)
#define SKT_EHPID_LEN (16)

#define SKT_BROADCAST_KEY ("Broadcast key")
#define SKT_BROADCAST_KEY_LEN (sizeof(SKT_BROADCAST_KEY)-1)

typedef struct dp3t_skt_t {
    uint8_t key[SKT_LEN];
} dp3t_skt_t;

typedef struct dp3t_eph_t {
    uint8_t id[SKT_EHPID_LEN];
} dp3t_eph_t;

typedef enum {
    DPT3T_OK,
    DPT3T_ERR,
} dp3t_err_t;

dp3t_err_t generate_skt( dp3t_skt_t * skt) {
    assert(sizeof(skt->key) == SHA256_DIGEST_LENGTH);
    assert(SKT_BITLEN/8 == SHA256_DIGEST_LENGTH);
    
    return (1 == RAND_bytes(skt->key, sizeof(skt->key))) ? DPT3T_OK : DPT3T_ERR;
}

dp3t_err_t set_skt( dp3t_skt_t * skt, char *hex_string) {
    if (strlen(hex_string) != SHA256_DIGEST_LENGTH*2)
        return DPT3T_ERR;
    
    for(int i = 0;i<SHA256_DIGEST_LENGTH;i++) {
        char bt[3] = { hex_string[(i<<1)+0], hex_string[(i<<1)+1], 0};
        skt->key[i]  = strtoul(bt, NULL,16);
    }
    
    return DPT3T_OK;
}


dp3t_err_t next_skt( dp3t_skt_t * nextkey, dp3t_skt_t * skt) {
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, skt->key,SKT_LEN);
    SHA256_Final(nextkey->key, &sha256);
    
    return DPT3T_OK;
}


void print_hex(uint8_t * buff, size_t len) {
    for(int i = 0; i < len; i++)
        printf("%02x", buff[i]);
    printf(" (%lu bytes)\n", len);
};

void print_skt( dp3t_skt_t * skt) {
    for(size_t i = 0; i < sizeof(skt->key); i++)
        printf("%02X",skt->key[i]);
    printf("\n");
}

void print_ephid( dp3t_eph_t * e) {
    for(size_t i = 0; i < sizeof(e->id); i++)
        printf("%02X",e->id[i]);
    printf("\n");
}

dp3t_err_t generate_ephids(dp3t_skt_t * skt, dp3t_eph_t list[], size_t num) {
    uint8_t aes_key[SHA256_DIGEST_LENGTH];
    unsigned int aes_key_len = SHA256_DIGEST_LENGTH;
    
    //  local PRF = SHA256:hmac(ACK.secret_day_key, BROADCAST_KEY)
    
    // 446563656e7472616c697a656420507269766163792d50726573657276696e672050726f78696d6974792054726163696e67
    // unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
    //
    HMAC(EVP_sha256(),
         skt->key, SKT_LEN,// HMAC- key (all 0's in this test)
         (const unsigned char*)SKT_BROADCAST_KEY, SKT_BROADCAST_KEY_LEN,  // key to be digested and signed
         aes_key, &aes_key_len);
    
    // d59d48e21935f3389e3bd3eb02cf66989190b7b09ed6c0a4b9616f49455c4f9a
    //
    printf("PRF:\t");print_hex(aes_key, SHA256_DIGEST_LENGTH);
    
    unsigned char * in = malloc(SKT_EHPID_LEN*num);assert(in);
    bzero(in,SKT_EHPID_LEN*num);

    uint8_t iv[SKT_EHPID_LEN];
    bzero(iv,SKT_EHPID_LEN);

/*  Start with a fresh counter each day and initialize AES in CTR mode
    prg = AES.new(prf, AES.MODE_CTR, counter = Counter.new(128, initial_value=0))
    ephIDs = []

    # Create the number of desired ephIDs by encrypting 0 bytes
    prg_data = prg.encrypt(b"\0" * 16 * NUM_EPOCHS_PER_DAY)

    for i in range(NUM_EPOCHS_PER_DAY):
       ephIDs.append(prg_data[i*16:i*16+16])
 */

#ifdef TINY
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, iv);

    AES_CTR_xcrypt_buffer(&ctx, in, SKT_EHPID_LEN*num);

    for(int i = 0; i < num; i++)
        memcpy(list[i].id,in + i * SKT_EHPID_LEN, SKT_EHPID_LEN);

#else    
    unsigned char * out = malloc(SKT_EHPID_LEN*num);assert(out);
    const EVP_CIPHER * cipher = EVP_aes_256_ctr();
    assert(EVP_CIPHER_iv_length(cipher) == 128/8);
    
    EVP_CIPHER_CTX * ctx;
    assert(ctx = EVP_CIPHER_CTX_new());
    EVP_CIPHER_CTX_init(ctx);
    
    assert(1 == EVP_EncryptInit(ctx, cipher, aes_key, iv));
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0, len2 = 0;
        
    assert(1 == EVP_EncryptUpdate(ctx, out, &len, in, SKT_EHPID_LEN*num));
    assert(len == SKT_EHPID_LEN*num);

    for(int i = 0; i < num; i++)
        memcpy(list[i].id,out + i* SKT_EHPID_LEN, SKT_EHPID_LEN);
    
    assert(1 == EVP_EncryptFinal(ctx, out + len, &len2));

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
#endif
 
    return 0;
}

int main(int argc, const char * argv[]) {
    RAND_poll();
    
    dp3t_skt_t skt_null;
    assert(DPT3T_OK == set_skt(&skt_null, "0000000000000000000000000000000000000000000000000000000000000000"));
    
    
    // 0000000000000000000000000000000000000000000000000000000000000000
    printf("Secret:     "); print_skt(&skt_null);
    
    // 42726f616463617374206b6579
    printf("Broadcast key:"); print_hex((unsigned char*)SKT_BROADCAST_KEY, SKT_BROADCAST_KEY_LEN);
    assert(13 == SKT_BROADCAST_KEY_LEN);
    
    dp3t_skt_t skt_1;
    assert(DPT3T_OK == next_skt(&skt_1, &skt_null));
    

    
    const int N = 10;
    dp3t_eph_t list[N];
    generate_ephids(&skt_null, list, N);
    for(int i = 0; i < N; i++ ) {
        printf("%008d ", i);
        print_ephid(&list[i]); // a747e729bf2e3de3ec6ecbdb0f889f5b
    }
    
    // 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
    printf("SKT1: "); print_skt(&skt_1);
};
