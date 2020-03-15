# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/cms.h>
"""

TYPES = """
typedef ... CMS_SIGNED;

typedef ... CMS_DIGEST;
typedef ... CMS_ENCRYPT;
typedef ... CMS_ENVELOPE;

typedef ... CMS_ContentInfo;

static const int CMS_TEXT;
static const int CMS_NOCERTS;
static const int CMS_NO_CONTENT_VERIFY;
static const int CMS_NO_ATTR_VERIFY;

static const int CMS_NOINTERN;
static const int CMS_NO_SIGNER_CERT_VERIFY;
static const int CMS_NOVERIFY;
static const int CMS_DETACHED;
static const int CMS_BINARY;
static const int CMS_NOATTR;
static const int CMS_NOSMIMECAP;
static const int CMS_NOOLDMIMETYPE;
static const int CMS_CRLFEOL;
static const int CMS_STREAM;
static const int CMS_NOCRL;
static const int CMS_PARTIAL;
static const int CMS_REUSE_DIGEST;
static const int CMS_USE_KEYID;
static const int CMS_DEBUG_DECRYPT;
static const int CMS_KEY_PARAM;
static const int CMS_ASCIICRLF;

"""

FUNCTIONS = """
CMS_ContentInfo *SMIME_read_CMS(BIO *, BIO **);
int SMIME_write_CMS(BIO *, CMS_ContentInfo *, BIO *, int);

void CMS_free(CMS_ContentInfo *);

CMS_ContentInfo *CMS_sign(X509 *, EVP_PKEY *, Cryptography_STACK_OF_X509 *,
                  BIO *, unsigned int);
int CMS_verify(CMS_ContentInfo *, Cryptography_STACK_OF_X509 *, X509_STORE *, BIO *,
                 BIO *, unsigned int);
Cryptography_STACK_OF_X509 *CMS_get0_signers(CMS_ContentInfo *);

CMS_ContentInfo *CMS_encrypt(Cryptography_STACK_OF_X509 *, BIO *,
                     const EVP_CIPHER *, unsigned int);
int CMS_decrypt(CMS_ContentInfo *, EVP_PKEY *, X509 *, BIO *, BIO *, unsigned int);

ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo*);

"""

CUSTOMIZATIONS = ""
