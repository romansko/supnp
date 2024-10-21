/*!
 * \addtogroup OpenSSL
 *
 * \file openssl_wrapper.h
 *
 * \brief Header file for wrapping OpenSSL logics - required by SUPnP.
 *
 * \author Roman Koifman
 */
#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"
#include <openssl/sha.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if UPNP_ENABLE_OPEN_SSL

#define OPENSSL_API_COMPAT 30000 /* OpenSSL 3.0.0 */

/* Forward declaration <openssl/types.h> */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;


/*!
 * \brief Initialize SUPnP secure layer.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int OpenSslInitializeWrapper();

/*!
 * \brief Helper function to free a PKEY.
 */
UPNP_EXPORT_SPEC void OpenSslFreePKey(
    /*! [IN] PKEY to free */
    EVP_PKEY **pKey);

/*!
 * \brief convert binary data to hex string.
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer on success, NULL on failure.
 */
UPNP_EXPORT_SPEC char *OpenSslBinaryToHexString(
    /*! [IN] binary data */
    const unsigned char *data,
    /*! [IN] size of binary data */
    size_t size);

/*!
 * \brief convert binary data to hex string.
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslHexStringToBinary(
    /*! [IN] hex string */
    const char *hex,
    /*! [OUT] pointer to store the size of the binary data */
    size_t *pSize);

/*!
 * \brief Load a public key from hex string.
 *
 * \note Remember to EVP_PKEY_free(pkey)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY *OpenSslLoadPublicKeyFromHex(
    /*! [IN] hex string */
    const char *hex);

/*!
 * \brief Load a private key from hex string.
 *
 * \note Remember to EVP_PKEY_free(pkey)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY *OpenSslLoadPrivateKeyFromHex(
    /*! [IN] hex string */
    const char *hex);

/*!
 * \brief Convert public key to bytes.
 *
 * \note Remember to free the return pointer.
 *
 * \return pointer to public key bytes on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslPublicKeyToBytes(
    /*! [IN] public key */
    EVP_PKEY *pPublicKey,
    /*! [OUT] pointer to store the size of the public key */
    size_t *pKeySize);

/*!
 * \brief Convert private key to bytes.
 *
 * \note Remember to free the return pointer.
 *
 * \return pointer to private key bytes on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslPrivateKeyToBytes(
    /*! [IN] private key */
    EVP_PKEY *pPrivateKey,
    /*! [OUT] pointer to store the size of the private key */
    size_t *pKeySize);

/*!
 * \brief Load a public key from PEM file.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY *OpenSslLoadPublicKeyFromPEM(
    /*! [IN] path to PEM file */
    const char *filepathPEM);

/*!
 * \brief Load a private key from PEM file.
 *
 * \note Remember to EVP_PKEY_free(loaded_public_key)
 *
 * \return EVP_PKEY* on success, NULL on failure.
 */
UPNP_EXPORT_SPEC EVP_PKEY *OpenSslLoadPrivateKeyFromPEM(
    /*! [IN] path to PEM file */
    const char *filepathPEM);

/*!
 * \brief Load a certificate from PEM string.
 *
 * \note Remember to X509_free(cert)
 *
 * \return X509 * certificate on success, NULL on failure.
 */
UPNP_EXPORT_SPEC X509 *OpenSslLoadCertificateFromString(
    /*! [IN] certificate in PEM format */
    const char *certString);

/*!
 * \brief Load a certificate from PEM file.
 *
 * \note Remember to X509_free(cert)
 *
 * \return X509 * certificate on success, NULL on failure.
 */
UPNP_EXPORT_SPEC X509 *OpenSslLoadCertificateFromPEM(
    /*! [IN] path to PEM file */
    const char *filepathPEM);

/*!
 * \brief Verify certificate.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int OpenSslVerifyCertificate(
    /*! [IN] name of the certificate */
    const char *name,
    /*! [IN] certificate */
    X509 *pCertificate,
    /*! [IN] public key */
    EVP_PKEY *pPublicKey);

/*!
 * \brief Verify signature.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int OpenSslVerifySignature(
    /*! [IN] name of the certificate */
    const char *name,
    /*! [IN] public key corresponding to the signature */
    EVP_PKEY *pPublicKey,
    /*! [IN] hex signature to verify */
    const char *hexSignature,
    /*! [IN] the data that was signed */
    const unsigned char *data,
    /*! [IN] size of the data */
    size_t size);

/*!
 * \brief Encrypt data
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to encrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslSymmetricEncryption(
    /*! [IN] symmetric key */
    const unsigned char *pKey,
    /*! [OUT] pointer to store the size of the encrypted data */
    int *pEncryptionSize,
    /*! [IN] data to encrypt */
    const unsigned char *data,
    /*! [IN] size of the data */
    size_t size);

/*!
 * \brief Decrypt data
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to decrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslSymmetricDecryption(
    /*! [IN] symmetric key */
    const unsigned char *pkey,
    /*! [OUT] pointer to store the size of the decrypted data */
    int *pDecryptionSize,
    /*! [IN] encrypted data */
    const unsigned char *encrypted,
    /*! [IN] size of the encrypted data */
    size_t size);

/*!
 * \brief Encrypt data using asymmetric key
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to encrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslAsymmetricEncryption(
    /*! [IN] public key */
    EVP_PKEY *pPublicKey,
    /*! [OUT] pointer to store the size of the encrypted data */
    size_t *pEncryptionSize,
    /*! [IN] data to encrypt */
    const unsigned char *data,
    /*! [IN] size of the data */
    size_t size);

/*!
 * \brief Decrypt data using asymmetric key
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to decrypted data on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslAsymmetricDecryption(
    /*! [IN] private key */
    EVP_PKEY *pPrivateKey,
    /*! [OUT] pointer to store the size of the decrypted data */
    size_t *pDecryptionSize,
    /*! [IN] encrypted data */
    const unsigned char *data,
    /*! [IN] size of the encrypted data */
    size_t size);



/*!
 * \brief Calculate SHA256 hash.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int OpenSslDoSHA256(
    /*! [OUT] pointer to store the hash */
    unsigned char hash[SHA256_DIGEST_LENGTH],
    /*! [IN] data to hash */
    const unsigned char *data,
    /*! [IN] size of the data */
    size_t size);

/*!
 * \brief Sign data.
 *
 * \note Remember to free the returned pointer.
 *
 * \return pointer to signature on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslSign(
    /*! [IN] private key to sign with */
    EVP_PKEY *pPrivateKey,
    /*! [IN] data to sign */
    const unsigned char *data,
    /*! [IN] size of the data */
    size_t size,
    /*! [OUT] pointer to store the size of the generated signature */
    size_t *pSignatureLength);

#endif /* UPNP_ENABLE_OPEN_SSL */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OPENSSL_WRAPPER_H
