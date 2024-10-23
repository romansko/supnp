/*!
 * \addtogroup OpenSSL
 *
 * \file openssl_wrapper.c
 *
 * \brief source file for wrapping OpenSSL logics - required by SUPnP.
 * developed with libssl-dev v3.0
 * https://www.openssl.org/docs/man3.0/index.html
 *
 * \author Roman Koifman
 */
#include "upnpconfig.h"
#include "file_utils.h"
#include "openssl_error.h"
#include "openssl_wrapper.h"
#include <openssl/evp.h>  /* EVP related */
#include <openssl/pem.h>  /* PEM related */
#include <openssl/sha.h>  /* For SHA256  */
#include <openssl/ssl.h>  /* OpenSSL Library Init */


#ifdef __cplusplus
extern "C" {
#endif

#if UPNP_ENABLE_OPEN_SSL

const char *OpenSslGetLastError()
{
    const char *err = ERR_error_string(ERR_get_error(), NULL);
    ERR_clear_error();
    return err;
}

// Obviously change in your apps..
const char *IV = "SUPNP_CHANGE_IV!"; /* 16 bytes IV for AES-256-CBC */

int gOpenSslInitialized = 0;

/**
 * Initialize SUPnP secure layer.
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int OpenSslInitializeWrapper()
{
    if (gOpenSslInitialized == 1) {
        w_log("OpenSSL already initialized.\n");
        return OPENSSL_FAILURE;
    }
    w_log("Initializing OpenSSL Wrapper..\n");
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    gOpenSslInitialized = 1;
    return OPENSSL_SUCCESS;
}

/**
 * Convert binary data to hex string.
 * @param data binary data
 * @param size the size of the data
 * @return hex string on success, NULL on failure
 */
char *OpenSslBinaryToHexString(const unsigned char *data, const size_t size)
{
    char *hex = NULL;
    w_verify(data, cleanup, "NULL data provided.\n");
    w_verify(size > 0, cleanup, "Invalid data size.\n");
    hex = malloc(size * 2 + 1);
    w_verify(hex, cleanup, "Error allocating memory for hex string.\n");
    for (size_t i = 0; i < size; ++i) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[size * 2] = '\0';
cleanup:
    return hex; /* remember to free(hex); */
}

/**
 * Convert a hex string to binary.
 * @param hex a hex string
 * @param pSize the size of the returned binary data
 * @return a binary representation of the hex string
 */
unsigned char *OpenSslHexStringToBinary(const char *hex, size_t *pSize)
{
    unsigned char *binary = NULL;
    w_verify(hex, cleanup, "NULL hex string provided.\n");
    w_verify(pSize, cleanup, "NULL data size ptr.\n");
    const size_t hex_len = strlen(hex);
    w_verify(hex_len % 2 == 0, cleanup, "Invalid hex string length %lu.\n",
        hex_len);
    *pSize = hex_len / 2;
    binary = malloc(*pSize);
    w_verify(binary, cleanup, "Error allocating memory for binary data.\n");
    for (size_t i = 0; i < hex_len; i += 2) {
        sscanf(hex + i, "%2hhx", &binary[i / 2]);
    }
cleanup:
    return binary; /* remember to free(binary); */
}

/**
 * Load a public key from a hex string.
 * The caller is responsible for freeing the public key.
 * @param hex a hex string representing a public key
 * @return a EVP_PKEY * public key on success, NULL on failure
 */
EVP_PKEY *OpenSslLoadPublicKeyFromHex(const char *hex)
{
    EVP_PKEY *pkey = NULL;
    size_t dsize = 0;
    unsigned char *bin = OpenSslHexStringToBinary(hex, &dsize);
    w_verify(bin, cleanup, "Error converting public key hex string.\n");
    const unsigned char *bin_copy = bin;
    pkey = d2i_PUBKEY(NULL, &bin_copy, (long)dsize);
    free(bin);
    w_verify(pkey, cleanup, "Error loading public key\n");
cleanup:
    return pkey; /* Remember to EVP_PKEY_free(pkey); */
}

/**
 * Load a private key from a hex string.
 * The caller is responsible for freeing the public key.
 * @param hex a hex string representing a private key
 * @return a EVP_PKEY * private key on success, NULL on failure
 */
EVP_PKEY *OpenSslLoadPrivateKeyFromHex(const char *hex)
{
    EVP_PKEY *pkey = NULL;
    size_t dsize = 0;
    unsigned char *bin = OpenSslHexStringToBinary(hex, &dsize);
    w_verify(bin, cleanup, "Error converting public key hex string.\n");
    const unsigned char *bin_copy = bin;
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bin_copy, (long)dsize);
    free(bin);
    w_verify(pkey, cleanup, "Error loading private key\n");
cleanup:
    return pkey; /* Remember to EVP_PKEY_free(pkey); */
}

/**
 * Helper function to free a PKEY object. This bypass the linker error:
 * undefined reference to symbol 'EVP_PKEY_free@@OPENSSL_3.0.0'
 * @param pKey a PKEY pointer
 */
void OpenSslFreePKey(EVP_PKEY **pKey)
{
    w_freeif(*pKey, EVP_PKEY_free);
}

/**
 * Helper function to free a X509 object.
 * @param pCert an X509 certificate pointer
 */
void OpenSslFreeCertificate(X509 **pCert)
{
    w_freeif(*pCert, X509_free);
}

/**
 * Convert a public key to bytes.
 * The caller is responsible for freeing the return pointer.
 * @param pPublicKey a public key
 * @param pKeySize a pointer to an integer to store the size of the returned
 * buffer
 * @return a pointer to the public key bytes on success, NULL on failure
 */
unsigned char *OpenSslPublicKeyToBytes(EVP_PKEY *pPublicKey, size_t *pKeySize)
{
    size_t size = 0;
    unsigned char *buffer = NULL;
    w_verify(pPublicKey, cleanup, "Empty public key provided.\n");
    size = i2d_PUBKEY(pPublicKey, &buffer);
    w_verify((size > 0) && (buffer),
        cleanup,
        "Error converting public key to bytes.\n");
cleanup:
    if (pKeySize)
        *pKeySize = size;
    return buffer; /* remember to free(buffer); */
}

/**
 * Convert a private key to bytes.
 * The caller is responsible for freeing the return pointer.
 * @param pPrivateKey a private key
 * @param pKeySize a pointer to an integer to store the size of the returned
 * buffer
 * @return a pointer to the private key bytes on success, NULL on failure
 */
unsigned char *OpenSslPrivateKeyToBytes(EVP_PKEY *pPrivateKey, size_t *pKeySize)
{
    size_t size = 0;
    unsigned char *buffer = NULL;
    w_verify(pPrivateKey, cleanup, "Empty private key provided.\n");
    size = i2d_PrivateKey(pPrivateKey, &buffer);
    w_verify((size > 0) && (buffer),
        cleanup,
        "Error converting private key to bytes.\n");
cleanup:
    if (pKeySize != NULL)
        *pKeySize = size;
    return buffer; /* remember to free(buffer); */
}

/**
 * Load a public key from a PEM file.
 * The caller is responsible for freeing the public key.
 * @param filepathPEM a path to a PEM file
 * @return a EVP_PKEY * public key on success, NULL on failure
 */
EVP_PKEY *OpenSslLoadPublicKeyFromPEM(const char *filepathPEM)
{
    EVP_PKEY *loaded_key = NULL;
    FILE *fp = NULL;
    macro_file_open(fp, filepathPEM, "r", cleanup);
    loaded_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    w_verify(loaded_key,
        cleanup,
        "Error loading public key from PEM file %s\n",
        filepathPEM);
cleanup:
    macro_file_close(fp);
    return loaded_key; /* Remember to EVP_PKEY_free(loaded_key); */
}

/**
 * Load a private key from a PEM file.
 * The object will also contain the public key calculated from the private key.
 * The caller is responsible for freeing the private key.
 * @param filepathPEM a path to a PEM file
 * @return a EVP_PKEY * private key on success, NULL on failure
 */
EVP_PKEY *OpenSslLoadPrivateKeyFromPEM(const char *filepathPEM)
{
    EVP_PKEY *loaded_key = NULL;
    FILE *fp = NULL;
    macro_file_open(fp, filepathPEM, "r", cleanup);
    loaded_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    w_verify(loaded_key,
        cleanup,
        "Error loading private key from PEM file %s\n",
        filepathPEM);
cleanup:
    macro_file_close(fp);
    return loaded_key; /* Remember to EVP_PKEY_free(loaded_key); */
}

/**
 * Load a certificate object from string.
 * The caller is responsible for freeing the certificate.
 * @param certString certificate string
 * @return a X509 * certificate on success, NULL on failure
 */
X509 *OpenSslLoadCertificateFromString(const char *certString)
{
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf((void *)certString, -1); // -1 = compute strlen
    w_verify(bio, cleanup, "Error creating BIO\n");
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL); // allocates new X509
    w_verify(cert, cleanup, "Error reading X509 certificate from string\n");

cleanup:
    w_freeif(bio, BIO_free);
    BIO_free(bio); // Clean up BIO

    return cert; /* Remember to X509_free(cert); */
}

/**
 * Load a certificate from a PEM file.
 * The caller is responsible for freeing the certificate.
 * @param filepathPEM a path to a PEM file
 * @return a X509 * certificate on success, NULL on failure
 */
X509 *OpenSslLoadCertificateFromPEM(const char *filepathPEM)
{
    X509 *cert = NULL;
    FILE *fp = NULL;
    macro_file_open(fp, filepathPEM, "r", cleanup);
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    w_verify(cert,
        cleanup,
        "Error loading certificate from PEM file %s\n",
        filepathPEM);
cleanup:
    macro_file_close(fp);
    return cert; /* Remember to X509_free(cert); */
}

/**
 * Verifies the signature of a certificate using public key.
 * Only the signature is checked: no other checks (such as certificate chain
 * validity) are performed.
 * @param name Certificate's name
 * @param pCertificate a certificate
 * @param pPublicKey a public key corresponding to the entity that signed the
 * certificate
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int OpenSslVerifyCertificate(
    const char *name, X509 *pCertificate, EVP_PKEY *pPublicKey)
{
    int ret = OPENSSL_FAILURE;
    w_log("Verifying '%s''s certificate..\n", name);
    w_verify(name, cleanup, "Empty certificate name provided.\n");
    w_verify(pCertificate, cleanup, "Empty certificate provided.\n");
    w_verify(pPublicKey, cleanup, "Empty CA public key provided.\n");
    ret = X509_verify(pCertificate, pPublicKey);
    w_verify(ret == OPENSSL_SUCCESS,
        cleanup,
        "'%s' certificate verification error\n",
        name);
cleanup:
    return ret;
}

/**
 * Verify signature.
 * @param name Signature's name
 * @param pPublicKey a public key corresponding to the entity that signed the
 * data
 * @param hexSignature a hex string representing the signature
 * @param data the data that was signed
 * @param size the size of the data
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
int OpenSslVerifySignature(const char *name,
    EVP_PKEY *pPublicKey,
    const char *hexSignature,
    const unsigned char *data,
    const size_t size)
{
    int ret = OPENSSL_FAILURE;
    unsigned char *sig = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t sig_size = 0;
    char pre[100] = { '\0'} ;

    if (name) {
        snprintf(pre, sizeof(pre) - 1, "'%s': ", name);
    }

    // Arguments Verification
    w_verify(pPublicKey, cleanup, "%sNULL public key provided.\n", pre);
    w_verify(hexSignature, cleanup, "%sNULL signature provided.\n", pre);
    w_verify(data, cleanup, "%sNULL data provided.\n", pre);
    w_verify(size > 0, cleanup, "%sInvalid data size provided.\n", pre);

    // Initialize context
    mdctx = EVP_MD_CTX_new();
    w_verify(mdctx, cleanup, "%sError creating EVP_MD_CTX.\n", pre);
    ret = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pPublicKey);
    w_verify(ret == OPENSSL_SUCCESS, cleanup, "%s", pre);
    ret = EVP_DigestVerifyUpdate(mdctx, data, size);
    w_verify(ret == OPENSSL_SUCCESS, cleanup, "%s", pre);
    sig = OpenSslHexStringToBinary(hexSignature, &sig_size);
    w_verify(sig, cleanup, "%sFailed to convert hex signature to bytes.\n", pre);

    // Verify signature
    ret = EVP_DigestVerifyFinal(mdctx, sig, sig_size);
    w_verify(ret == OPENSSL_SUCCESS, cleanup, "%s", pre);

cleanup:
    w_freeif(mdctx, EVP_MD_CTX_free);
    w_freeif(sig, free);

    return ret;
}

/**
 * Encrypt data using symmetric key.
 * The caller is responsible for freeing the return pointer.
 * @param pKey a symmetric key
 * @param enc_size a pointer to an integer to store the size of the returned
 * buffer
 * @param data the data to encrypt
 * @param size the size of the data
 * @return a pointer to the encrypted data on success, NULL on failure
 * @note The IV is hardcoded in this function.
 */
unsigned char *OpenSslSymmetricEncryption(const unsigned char *pKey,
    int *enc_size,
    const unsigned char *data,
    size_t size)
{
    const unsigned char *iv = (const unsigned char *)IV; /* Change IV */
    unsigned char *encrypted = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int final_len = 0; /* Only for final stage encyption */
    unsigned char buffer[1024];

    // Verify Key
    w_verify(pKey, cleanup, "Empty private key provided.\n");

    // Initialize context
    ctx = EVP_CIPHER_CTX_new();
    w_verify(ctx, cleanup, "Error creating EVP_CIPHER_CTX.\n");
    w_verify(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pKey, iv) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Encryption error.\n");

    // Encryption
    *enc_size = 0;
    w_verify(
        EVP_EncryptUpdate(ctx, buffer, enc_size, data, size) == OPENSSL_SUCCESS,
        cleanup,
        "Encryption error.\n");
    w_verify(EVP_EncryptFinal_ex(ctx, (buffer + *enc_size), &final_len) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Encryption error.\n");
    *enc_size += final_len;

    // allocate memory for the encrypted data
    w_verify(*enc_size > 0, cleanup, "Encryption error.\n");
    encrypted = malloc(*enc_size);
    w_verify(
        encrypted, cleanup, "Error allocating memory for encrypted data.\n");
    memcpy(encrypted, buffer, *enc_size);

cleanup:
    w_freeif(ctx, EVP_CIPHER_CTX_free);
    return encrypted;
}

/**
 * Decrypt data using symmetric key.
 * The caller is responsible for freeing the return pointer.
 * @param pkey a symmetric key
 * @param pDecryptionSize a pointer to an integer to store the size of the
 * returned buffer
 * @param encrypted the data to decrypt
 * @param size the size of the data
 * @return a pointer to the decrypted data on success, NULL on failure
 * @note The IV is hardcoded in this function.
 */
unsigned char *OpenSslSymmetricDecryption(const unsigned char *pkey,
    int *pDecryptionSize,
    const unsigned char *encrypted,
    const size_t size)
{
    const unsigned char *iv = (const unsigned char *)IV; /* Change IV */
    int dec_size = 0;
    unsigned char *decrypted = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int final_len = 0; /* Only for final stage decryption */
    unsigned char buffer[1024];

    // Verify Key
    w_verify(pkey, cleanup, "Empty private key provided.\n");

    // Initialize context
    ctx = EVP_CIPHER_CTX_new();
    w_verify(ctx, cleanup, "Error creating EVP_CIPHER_CTX.\n");
    w_verify(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pkey,
        iv) ==  OPENSSL_SUCCESS, cleanup, "Decryption error.\n");

    // Decryption
    w_verify(EVP_DecryptUpdate(ctx, buffer, &dec_size, encrypted, size) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Decryption error.\n");
    w_verify(EVP_DecryptFinal_ex(ctx, buffer + dec_size, &final_len) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Decryption error.\n");
    dec_size += final_len;
    EVP_CIPHER_CTX_free(ctx);

    // Allocate memory for the decrypted data
    w_verify(dec_size > 0, cleanup, "Decryption error.\n");
    decrypted = malloc(dec_size);
    w_verify(
        decrypted, cleanup, "Error allocating memory for decrypted data.\n");
    memcpy(decrypted, buffer, dec_size);

cleanup:
    if (pDecryptionSize)
        *pDecryptionSize = dec_size;
    w_freeif(ctx, EVP_CIPHER_CTX_free);
    return decrypted;
}

/**
 * Encrypt data using asymmetric key.
 * The caller is responsible for freeing the returned pointer.
 * @param pPublicKey a public key
 * @param pEncryptionSize a pointer to a size_t to store the size of the
 * returned buffer
 * @param data the data to encrypt
 * @param size the size of the data
 * @return a pointer to the encrypted data on success, NULL on failure
 * @note implemented according to
 * https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
 */
unsigned char *OpenSslAsymmetricEncryption(EVP_PKEY *pPublicKey,
    size_t *pEncryptionSize,
    const unsigned char *data,
    const size_t size)
{
    size_t enc_size = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *encrypted = NULL;

    // verify arguments
    w_verify(pPublicKey, cleanup, "NULL key provided.\n");
    w_verify(data, cleanup, "NULL data provided.\n");
    w_verify(size > 0, cleanup, "Invalid data size provided.\n");

    // Initialize context
    ctx = EVP_PKEY_CTX_new(pPublicKey, NULL);
    // eng = NULL ->start with the default OpenSSL RSA implementation
    w_verify(ctx, cleanup, "Error creating EVP_PKEY_CTX.\n");
    w_verify(EVP_PKEY_encrypt_init(ctx) == OPENSSL_SUCCESS,
        cleanup,
        "Encryption init error.\n");
    w_verify(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Set padding error.\n");

    // retrieve the encryption size & allocate memory
    w_verify(
        EVP_PKEY_encrypt(ctx, NULL, &enc_size, data, size) == OPENSSL_SUCCESS,
        cleanup,
        "Unable to retrieve encryption length.\n");
    encrypted = malloc(enc_size);
    w_verify(
        encrypted, cleanup, "Error allocating memory for encrypted data.\n");

    // Encrypt data
    w_verify(EVP_PKEY_encrypt(ctx, encrypted, &enc_size, data, size) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Encryption error.\n");
    goto success;

cleanup:
    w_freeif(encrypted, free);

success:
    if (pEncryptionSize)
        *pEncryptionSize = enc_size;
    w_freeif(ctx, EVP_PKEY_CTX_free);
    return encrypted;
}

/**
 * Decrypt data using asymmetric key.
 * The caller is responsible for freeing the returned pointer.
 * @param pPrivateKey a private key
 * @param pDecryptionSize a pointer to a size_t to store the size of the
 * returned buffer
 * @param data the data to decrypt
 * @param size the size of the data
 * @return a pointer to the decrypted data on success, NULL on failure
 * @note implemented according to
 * https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html
 */
unsigned char *OpenSslAsymmetricDecryption(EVP_PKEY *pPrivateKey,
    size_t *pDecryptionSize,
    const unsigned char *data,
    const size_t size)
{
    size_t dec_size = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *decrypted = NULL;

    // verify arguments
    w_verify(pPrivateKey, cleanup, "NULL key provided.\n");
    w_verify(data, cleanup, "NULL data provided.\n");
    w_verify(size > 0, cleanup, "Invalid data size provided.\n");

    // Initialize context
    ctx = EVP_PKEY_CTX_new(pPrivateKey, NULL);
    // eng = NULL ->start with the default OpenSSL RSA implementation
    w_verify(ctx, cleanup, "Error creating EVP_PKEY_CTX.\n");
    w_verify(EVP_PKEY_decrypt_init(ctx) == OPENSSL_SUCCESS,
        cleanup,
        "Decryption init error.\n");
    w_verify(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Set padding error.\n");

    // retrieve the decryption size & allocate memory
    w_verify(
        EVP_PKEY_decrypt(ctx, NULL, &dec_size, data, size) == OPENSSL_SUCCESS,
        cleanup,
        "Unable to retrieve decryption length.\n");
    decrypted = malloc(dec_size);
    w_verify(
        decrypted, cleanup, "Error allocating memory for decrypted data.\n");

    // Decrypt data
    w_verify(EVP_PKEY_decrypt(ctx, decrypted, &dec_size, data, size) ==
                 OPENSSL_SUCCESS,
        cleanup,
        "Decryption error.\n");
    goto success;

cleanup:
    w_freeif(decrypted, free);

success:
    if (pDecryptionSize)
        *pDecryptionSize = dec_size;
    w_freeif(ctx, EVP_PKEY_CTX_free);
    return decrypted;
}



/**
 * Calculate SHA256 hash.
 * https://www.openssl.org/docs/man3.0/man3/SHA256.html
 * @param hash the hash buffer
 * @param data the data to hash
 * @param size the size of the data
 * @return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure
 */
int OpenSslDoSHA256(unsigned char hash[SHA256_DIGEST_LENGTH],
    const unsigned char *data,
    const size_t size)
{
    int ret = OPENSSL_FAILURE;
    w_verify(data, cleanup, "Empty data provided.\n");
    w_verify(size > 0, cleanup, "Invalid data size.\n");
    w_verify(SHA256(data, size, hash) == hash,
        cleanup,
        "SHA256 calculation failed\n");
    ret = OPENSSL_SUCCESS;
cleanup:
    return ret;
}

/**
 * Sign data using pkey by calculating sha256 and encrypting the hash.
 * @param pPrivateKey private key
 * @param data data to be signed
 * @param size size of data
 * @param pSignatureLength the size of the returned signature
 * @return signed data on success, NULL on failure
 */
unsigned char *OpenSslSign(EVP_PKEY *pPrivateKey,
    const unsigned char *data,
    const size_t size,
    size_t *pSignatureLength)
{
    int ret = OPENSSL_FAILURE;
    unsigned char *signature = NULL;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    w_verify(pPrivateKey, error, "NULL private key provided.\n");
    w_verify(data, error, "NULL data provided.\n");
    w_verify(size > 0, error, "Invalid data size provided.\n");
    w_verify(pSignatureLength, error, "NULL signature length ptr.\n");

    // Initialize the context for signing with the private key
    ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pPrivateKey);
    w_verify(
        ret == OPENSSL_SUCCESS, error, "Error initializing signing context\n");

    // Add data to be signed
    ret = EVP_DigestSignUpdate(mdctx, data, size);
    w_verify(ret == OPENSSL_SUCCESS, error, "Error adding data to be signed\n");

    // Determine the length of the signature
    ret = EVP_DigestSignFinal(mdctx, NULL, pSignatureLength);
    w_verify(
        ret == OPENSSL_SUCCESS, error, "Error determining signature length\n");

    // Allocate memory for the signature
    signature = malloc(*pSignatureLength);
    w_verify(signature, error, "Error allocating memory for signature\n");

    // Generate the signature
    ret = EVP_DigestSignFinal(mdctx, signature, pSignatureLength);
    w_verify(ret == OPENSSL_SUCCESS, error, "Error generating signature\n");

    goto success;

error:
    w_freeif(signature, free);
success:
    w_freeif(mdctx, EVP_MD_CTX_free);
    return signature;
}

#endif /* UPNP_ENABLE_OPEN_SSL */

#ifdef __cplusplus
}
#endif /* __cplusplus */