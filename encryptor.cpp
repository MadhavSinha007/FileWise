#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define AES_KEY_SIZE 32  // AES-256 requires a 32-byte key
#define AES_IV_SIZE 12   // Recommended IV size for GCM mode
#define GCM_TAG_SIZE 16  // Authentication tag size

using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

vector<unsigned char> generateAESKey() {
    vector<unsigned char> key(AES_KEY_SIZE);
    if (!RAND_bytes(key.data(), AES_KEY_SIZE)) handleErrors();
    return key;
}

vector<unsigned char> encryptAES(const vector<unsigned char> &plaintext, const vector<unsigned char> &key, vector<unsigned char> &iv, vector<unsigned char> &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    iv.resize(AES_IV_SIZE);
    if (!RAND_bytes(iv.data(), AES_IV_SIZE)) handleErrors();

    vector<unsigned char> ciphertext(plaintext.size());
    int len, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data())) handleErrors();

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) handleErrors();
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;

    tag.resize(GCM_TAG_SIZE);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data())) handleErrors();

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

vector<unsigned char> decryptAES(const vector<unsigned char> &ciphertext, const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    vector<unsigned char> decrypted(ciphertext.size());
    int len, decrypted_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data())) handleErrors();

    if (!EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size())) handleErrors();
    decrypted_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void *)tag.data())) handleErrors();

    if (!EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len)) {
        cerr << "Decryption failed! Possible data corruption or incorrect key." << endl;
        exit(1);
    }
    decrypted_len += len;

    decrypted.resize(decrypted_len);
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

EVP_PKEY *loadPublicKey(const string &filename) {
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) {
        cerr << "Error: Unable to open public key file." << endl;
        exit(1);
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

EVP_PKEY *loadPrivateKey(const string &filename) {
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) {
        cerr << "Error: Unable to open private key file." << endl;
        exit(1);
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

vector<unsigned char> encryptAESKeyWithRSA(const vector<unsigned char> &aesKey, EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    size_t encryptedLen;
    if (EVP_PKEY_encrypt(ctx, NULL, &encryptedLen, aesKey.data(), aesKey.size()) <= 0) handleErrors();

    vector<unsigned char> encryptedKey(encryptedLen);
    if (EVP_PKEY_encrypt(ctx, encryptedKey.data(), &encryptedLen, aesKey.data(), aesKey.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return encryptedKey;
}

vector<unsigned char> decryptAESKeyWithRSA(const vector<unsigned char> &encryptedKey, EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    size_t decryptedLen;
    if (EVP_PKEY_decrypt(ctx, NULL, &decryptedLen, encryptedKey.data(), encryptedKey.size()) <= 0) handleErrors();

    vector<unsigned char> decryptedKey(decryptedLen);
    if (EVP_PKEY_decrypt(ctx, decryptedKey.data(), &decryptedLen, encryptedKey.data(), encryptedKey.size()) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return decryptedKey;
}

int main() {
    cout << "OpenSSL 3.0 Encryption/Decryption with AES-256-GCM and RSA." << endl;
    return 0;
}