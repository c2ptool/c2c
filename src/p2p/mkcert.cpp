#include "mkcert.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#include <iostream>
#include <fstream>
#include <memory>

using std::unique_ptr;

namespace c2c {

std::string to_hex(const std::string& bin);

struct RSA_del { void operator()(RSA *p) { RSA_free(p); } };
struct BN_del { void operator()(BIGNUM *p) { BN_free(p); } };
struct X509_del { void operator()(X509 *p) { X509_free(p); } };
struct EVP_PKEY_del { void operator()(EVP_PKEY *p) { EVP_PKEY_free(p); } };
struct BIO_del { void operator()(BIO *p) { BIO_free(p); } };

using RSA_ptr = std::unique_ptr<RSA, RSA_del>;
using BN_ptr = std::unique_ptr<BIGNUM, BN_del>;
using X509_ptr = std::unique_ptr<X509, X509_del>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_del>;
using BIO_ptr = std::unique_ptr<BIO, BIO_del>;

/*
 * Add extension using V3 code: we can set the config file as nullptr because we
 * wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, const char *value);

bool mkcert(int bits, long serial_number, long days, std::string& key, std::string& crt, std::string& digest)
{
    BN_ptr bne(BN_new());
    if(BN_set_word(bne.get(), RSA_F4) != 1)
        return false;

    RSA_ptr r(RSA_new());
    if(RSA_generate_key_ex(r.get(), bits, bne.get(), nullptr) != 1)
        return false;

    BIO_ptr bio_pk(BIO_new(BIO_s_mem()));
    if(PEM_write_bio_RSAPrivateKey(bio_pk.get(), r.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
        return false;

    long len = BIO_ctrl(bio_pk.get(), BIO_CTRL_PENDING, 0, nullptr);
    if(len == 0)
        return false;
    key.assign(size_t(len), char(0));
    BIO_read(bio_pk.get(), (void *)key.data(), int(len));

    X509_ptr x(X509_new());
    EVP_PKEY_ptr pk(EVP_PKEY_new());

    if (!EVP_PKEY_assign(pk.get(), EVP_PKEY_RSA, r.get()))
        return false;

    r.release();

    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), serial_number);
    X509_gmtime_adj(X509_get_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x.get()), long(60 * 60 * 24 * days));
    X509_set_pubkey(x.get(), pk.get());

    EVP_PKEY *pk_ptr = pk.release();

    X509_NAME *name = X509_get_subject_name(x.get());

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"C2C", -1, -1, 0);

    X509_set_issuer_name(x.get(), name);

    /* Add various extensions: standard extensions */
    //add_ext(x.get(), NID_basic_constraints, "critical,CA:TRUE");
    //add_ext(x.get(), NID_key_usage, "critical,keyCertSign,cRLSign");

    //add_ext(x.get(), NID_subject_key_identifier, "hash");
    //add_ext(x.get(), NID_netscape_cert_type, "sslCA");
    //add_ext(x.get(), NID_netscape_comment, "example comment extension");

    //{
        //int nid;
        //nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        //X509V3_EXT_add_alias(nid, NID_netscape_comment);
        //add_ext(x.get(), nid, "example comment alias");
    //}

    if (!X509_sign(x.get(), pk_ptr, EVP_sha1()))
        return false;

    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD *md_sha1 = EVP_get_digestbyname("sha1");
    unsigned int n;
    if (!X509_digest(x.get(), md_sha1, md, &n))
        return false;

    digest = to_hex(std::string((const char *)md, 20));

    BIO_ptr bio_x(BIO_new(BIO_s_mem()));
    if(PEM_write_bio_X509(bio_x.get(), x.get()) != 1)
        return false;

    len = BIO_ctrl(bio_x.get(), BIO_CTRL_PENDING, 0, nullptr);
    if(len == 0)
        return false;

    crt.assign(size_t(len), char(0));
    BIO_read(bio_x.get(), (void *)crt.data(), int(len));

    return true;
}

/*
 * Add extension using V3 code: we can set the config file as nullptr because we
 * wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
     * Issuer and subject certs: both the target since it is self signed, no
     * request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

std::string to_hex(const std::string& bin)
{
    std::string out;
    std::string hex = "0123456789abcdef";

    for (size_t i = 0; i < bin.size(); i++) {
        out += hex[(bin[i] & 0xF0) >> 4];
        out += hex[bin[i] & 0x0F];
    }
    return out;
}

const std::string& DH_params()
{
    static const std::string params =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIICCAKCAgEA9L1CiTDVKtgQsqPLIjofcZl5+d0vOsSQhCDfm3YJjMFN6Gno3M0L\n"
    "9+DIXotk6C86KSKBPWIFLEexmJ8lMSFoX/UGZg5PdyU4048RbGmkA5INkZpVxRQr\n"
    "5Ldh/Xotvle7BuoHxVZ8jGZHOyTtzxHoAP+weuI1gggHs71jor/drYwh9XAr8Ihq\n"
    "H9yQ76xutIjvs4i9FJawsf/Dh0ObIhFAsbwVtT+Ns8nd51v71vu84e4/wOWhEeSD\n"
    "4oPAjJLNAU49ZZ0Ezu6jneFct67MAGakvXqhRtht3kFMaxI3bGblANq8RaM+/YRB\n"
    "QMHYVoGasQSEofCiQDu4CvhNj2Yo8XH2zdyREfWGO0z8XdJAp8fouZ8WnKwihaSN\n"
    "1ZkneMAEMMMvRWIV3yQ03JRGwkAogPol9H13sMOdzy7JMeVGwPrF1cQOvqzTAJN1\n"
    "uAG2rvkVI/kCvCwsZHiiKd/jKeUd07E/2fTh8NIwu+cwFxekjNwg6Fjp910hInN3\n"
    "B8Mg3sMUSh9RrIv0p0ia/+zCRP7uP0SaAZUORQc6MszBdIKodQWuqxHsxGsKOod9\n"
    "tQzJbWNQzqZ5wFQEJM/GD3LqLF0bYMAdm1KRGMxs+gmJvI1l3tbhwgCYNUfjZ0WD\n"
    "4xHP9AcpBkNIfmzON25VntpJQjsQfnv+Qme4zeU9g9Unh5lf162sf8sCAQI=\n"
    "-----END DH PARAMETERS-----";
    return params;
}

bool get_digest_crt(const std::string& crt, std::string& digest)
{
    BIO_ptr bio_x(BIO_new(BIO_s_mem()));
    BIO_read(bio_x.get(), (char *)crt.data(), crt.length());

    X509_ptr x_ptr(PEM_read_bio_X509(bio_x.get(), nullptr, nullptr, nullptr));
    if(!x_ptr)
        return false;

    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD *md_sha1 = EVP_get_digestbyname("sha1");
    unsigned int n;
    if (!X509_digest(x_ptr.get(), md_sha1, md, &n))
        return false;

    digest = to_hex(std::string((const char *)md, 20));
    return true;
}

bool get_digest_crt_file(const std::string& crt, std::string& digest)
{
    std::ifstream f(crt);
    if(!f.is_open())
        return false;
    std::string buf;
    f >> buf;
    return get_digest_crt(buf, digest);
}

}