/* ssl/t1_enc.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include <string.h>
#include "ssl_locl.h"
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#ifdef KSSL_DEBUG
# include <openssl/des.h>
#endif

/* seed1 through seed5 are virtually concatenated */
static int tls1_P_hash(const EVP_MD *md, const unsigned char *sec,
                       int sec_len,
                       const void *seed1, int seed1_len,
                       const void *seed2, int seed2_len,
                       const void *seed3, int seed3_len,
                       const void *seed4, int seed4_len,
                       const void *seed5, int seed5_len,
                       unsigned char *out, int olen)
{
    int chunk;
    size_t j;
    EVP_MD_CTX ctx, ctx_tmp, ctx_init;
    EVP_PKEY *mac_key;
    unsigned char A1[EVP_MAX_MD_SIZE];
    size_t A1_len;
    int ret = 0;

    chunk = EVP_MD_size(md);
    OPENSSL_assert(chunk >= 0);

    EVP_MD_CTX_init(&ctx);
    EVP_MD_CTX_init(&ctx_tmp);
    EVP_MD_CTX_init(&ctx_init);
    EVP_MD_CTX_set_flags(&ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
    if (!mac_key)
        goto err;
    if (!EVP_DigestSignInit(&ctx_init, NULL, md, NULL, mac_key))
        goto err;
    if (!EVP_MD_CTX_copy_ex(&ctx, &ctx_init))
        goto err;
    if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
        goto err;
    if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
        goto err;
    if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
        goto err;
    if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
        goto err;
    if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
        goto err;
    if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
        goto err;

    for (;;) {
        /* Reinit mac contexts */
        if (!EVP_MD_CTX_copy_ex(&ctx, &ctx_init))
            goto err;
        if (!EVP_DigestSignUpdate(&ctx, A1, A1_len))
            goto err;
        if (olen > chunk && !EVP_MD_CTX_copy_ex(&ctx_tmp, &ctx))
            goto err;
        if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
            goto err;
        if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
            goto err;
        if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
            goto err;
        if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
            goto err;
        if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
            goto err;

        if (olen > chunk) {
            if (!EVP_DigestSignFinal(&ctx, out, &j))
                goto err;
            out += j;
            olen -= j;
            /* calc the next A1 value */
            if (!EVP_DigestSignFinal(&ctx_tmp, A1, &A1_len))
                goto err;
        } else {                /* last one */

            if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
                goto err;
            memcpy(out, A1, olen);
            break;
        }
    }
    ret = 1;
 err:
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_cleanup(&ctx);
    EVP_MD_CTX_cleanup(&ctx_tmp);
    EVP_MD_CTX_cleanup(&ctx_init);
    OPENSSL_cleanse(A1, sizeof(A1));
    return ret;
}

/* seed1 through seed5 are virtually concatenated */
static int tls1_PRF(long digest_mask,
                    const void *seed1, int seed1_len,
                    const void *seed2, int seed2_len,
                    const void *seed3, int seed3_len,
                    const void *seed4, int seed4_len,
                    const void *seed5, int seed5_len,
                    const unsigned char *sec, int slen,
                    unsigned char *out1, unsigned char *out2, int olen)
{
    int len, i, idx, count;
    const unsigned char *S1;
    long m;
    const EVP_MD *md;
    int ret = 0;

    /* Count number of digests and partition sec evenly */
    count = 0;
    for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
        if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask)
            count++;
    }
    if (!count) {
        /* Should never happen */
        SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    len = slen / count;
    if (count == 1)
        slen = 0;
    S1 = sec;
    memset(out1, 0, olen);
    for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
        if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask) {
            if (!md) {
                SSLerr(SSL_F_TLS1_PRF, SSL_R_UNSUPPORTED_DIGEST_TYPE);
                goto err;
            }
            if (!tls1_P_hash(md, S1, len + (slen & 1),
                             seed1, seed1_len, seed2, seed2_len, seed3,
                             seed3_len, seed4, seed4_len, seed5, seed5_len,
                             out2, olen))
                goto err;
            S1 += len;
            for (i = 0; i < olen; i++) {
                out1[i] ^= out2[i];
            }
        }
    }
    ret = 1;
 err:
    return ret;
}

static int tls1_generate_key_block(SSL *s, unsigned char *km,
                                   unsigned char *tmp, int num)
{
    int ret;
    ret = tls1_PRF(ssl_get_algorithm2(s),
                   TLS_MD_KEY_EXPANSION_CONST,
                   TLS_MD_KEY_EXPANSION_CONST_SIZE, s->s3->server_random,
                   SSL3_RANDOM_SIZE, s->s3->client_random, SSL3_RANDOM_SIZE,
                   NULL, 0, NULL, 0, s->session->master_key,
                   s->session->master_key_length, km, tmp, num);
#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_generate_key_block() ==> %d byte master_key =\n\t",
            s->session->master_key_length);
    {
        int i;
        for (i = 0; i < s->session->master_key_length; i++) {
            fprintf(stderr, "%02X", s->session->master_key[i]);
        }
        fprintf(stderr, "\n");
    }
#endif                          /* KSSL_DEBUG */
    return ret;
}

int tls1_change_cipher_state(SSL *s, int which)
{
	// printf("[VTTLS] %s: Change cipher state\n", __func__);

    static const unsigned char empty[] = "";
    unsigned char *p, *mac_secret;
    unsigned char *exp_label;
    unsigned char tmp1[EVP_MAX_KEY_LENGTH];
    unsigned char tmp2[EVP_MAX_KEY_LENGTH];
    unsigned char iv1[EVP_MAX_IV_LENGTH * 2];
    unsigned char iv2[EVP_MAX_IV_LENGTH * 2];
    unsigned char *ms, *key, *iv;
    int client_write;
    EVP_CIPHER_CTX *dd;
    const EVP_CIPHER *c;
#ifndef OPENSSL_NO_COMP
    const SSL_COMP *comp;
#endif
    const EVP_MD *m;
    int mac_type;
    int *mac_secret_size;
    EVP_MD_CTX *mac_ctx;
    EVP_PKEY *mac_key;
    int is_export, n, i, j, k, exp_label_len, cl;
    int reuse_dd = 0;

    /***** VTTLS VARIABLES *****/
    unsigned char *p_sec, *mac_secret_sec;
    unsigned char *exp_label_sec;
    unsigned char iv3[EVP_MAX_IV_LENGTH * 2];
    unsigned char iv4[EVP_MAX_IV_LENGTH * 2];
    unsigned char *ms_sec, *key_sec, *iv_sec;
    EVP_CIPHER_CTX *dd_sec;
    const EVP_CIPHER *c_sec;
#ifndef OPENSSL_NO_COMP
    const SSL_COMP *comp_sec;
#endif
    const EVP_MD *m_sec;
    int mac_type_sec;
    int *mac_secret_size_sec;
    EVP_MD_CTX *mac_ctx_sec;
    EVP_PKEY *mac_key_sec;
    int is_export_sec, nn, ii, jj, k_sec, exp_label_len_sec, cl_sec;
    int reuse_dd_sec = 0;


    is_export     = SSL_C_IS_EXPORT(s->s3->tmp.new_cipher);
    is_export_sec = SSL_C_IS_EXPORT(s->s3->tmp.new_cipher_sec);

    c     = s->s3->tmp.new_sym_enc;
    c_sec = s->s3->tmp.new_sec_sym_enc;

    m     = s->s3->tmp.new_hash;
    m_sec = s->s3->tmp.new_hash_sec;

    mac_type     = s->s3->tmp.new_mac_pkey_type;
    mac_type_sec = s->s3->tmp.new_mac_pkey_type_sec;


#ifndef OPENSSL_NO_COMP
    comp     = s->s3->tmp.new_compression;
    comp_sec = s->s3->tmp.new_compression_sec;
#endif

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_change_cipher_state(which= %d) w/\n", which);
    fprintf(stderr, "\talg= %ld/%ld, comp= %p\n",
            s->s3->tmp.new_cipher->algorithm_mkey,
            s->s3->tmp.new_cipher->algorithm_auth, comp);
    fprintf(stderr, "\tevp_cipher == %p ==? &d_cbc_ede_cipher3\n", c);
    fprintf(stderr, "\tevp_cipher: nid, blksz= %d, %d, keylen=%d, ivlen=%d\n",
            c->nid, c->block_size, c->key_len, c->iv_len);
    fprintf(stderr, "\tkey_block: len= %d, data= ",
            s->s3->tmp.key_block_length);
    {
        int i;
        for (i = 0; i < s->s3->tmp.key_block_length; i++)
            fprintf(stderr, "%02x", s->s3->tmp.key_block[i]);
        fprintf(stderr, "\n");
    }
#endif                          /* KSSL_DEBUG */

    if (which & SSL3_CC_READ) {
        if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
        else
            s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

        if (s->s3->tmp.new_cipher_sec->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags_sec |= SSL_MAC_FLAG_READ_MAC_STREAM;
        else
            s->mac_flags_sec &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

        if (s->enc_read_ctx != NULL)
            reuse_dd = 1;
        else if ((s->enc_read_ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
            goto err;
        else
            EVP_CIPHER_CTX_init(s->enc_read_ctx);

        if (s->sec_enc_read_ctx != NULL)
        	reuse_dd_sec = 1;
        else if ((s->sec_enc_read_ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
        	goto err;
        else
            EVP_CIPHER_CTX_init(s->sec_enc_read_ctx);

        dd     = s->enc_read_ctx;
        dd_sec = s->sec_enc_read_ctx;

        mac_ctx     = ssl_replace_hash(&s->read_hash,     NULL);
        mac_ctx_sec = ssl_replace_hash(&s->read_hash_sec, NULL);

        if (mac_ctx == NULL || mac_ctx_sec == NULL)
            goto err;

#ifndef OPENSSL_NO_COMP /* TODO: Diversify this part */
        if (s->expand != NULL) {
            COMP_CTX_free(s->expand);
            s->expand = NULL;
        }
        if (comp != NULL) {
            s->expand = COMP_CTX_new(comp->method);
            if (s->expand == NULL) {
                SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE,
                       SSL_R_COMPRESSION_LIBRARY_ERROR);
                goto err2;
            }
            if (s->s3->rrec.comp == NULL)
                s->s3->rrec.comp = (unsigned char *)
                    OPENSSL_malloc(SSL3_RT_MAX_ENCRYPTED_LENGTH);
            if (s->s3->rrec.comp == NULL)
                goto err;
        }
#endif

        /*
         * this is done by dtls1_reset_seq_numbers for DTLS
         */
        if (!SSL_IS_DTLS(s)){
            memset(&(s->s3->read_sequence[0]), 0, 8);
            memset(&(s->s3->read_sequence_sec[0]), 0, 8);
        }


        mac_secret = &(s->s3->read_mac_secret[0]);
        mac_secret_size = &(s->s3->read_mac_secret_size);

        mac_secret_sec = &(s->s3->read_mac_secret_sec[0]);
        mac_secret_size_sec = &(s->s3->read_mac_secret_size_sec);

    } else {

        if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags |= SSL_MAC_FLAG_WRITE_MAC_STREAM;
        else
            s->mac_flags &= ~SSL_MAC_FLAG_WRITE_MAC_STREAM;

        if (s->s3->tmp.new_cipher_sec->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags_sec |= SSL_MAC_FLAG_WRITE_MAC_STREAM;
        else
            s->mac_flags_sec &= ~SSL_MAC_FLAG_WRITE_MAC_STREAM;


        if (s->enc_write_ctx != NULL && !SSL_IS_DTLS(s))
            reuse_dd = 1;
        else if ((s->enc_write_ctx = EVP_CIPHER_CTX_new()) == NULL)
            goto err;

        dd = s->enc_write_ctx;


        if (s->sec_enc_write_ctx != NULL && !SSL_IS_DTLS(s))
        	reuse_dd_sec = 1;
        else if ((s->sec_enc_write_ctx = EVP_CIPHER_CTX_new()) == NULL)
        	goto err;

        dd_sec = s->sec_enc_write_ctx;


        if (SSL_IS_DTLS(s)) {
            mac_ctx = EVP_MD_CTX_create();
            mac_ctx_sec = EVP_MD_CTX_create();
            if (mac_ctx == NULL || mac_ctx_sec == NULL)
                goto err;
            s->write_hash     = mac_ctx;
            s->write_hash_sec = mac_ctx_sec;
        } else {
            mac_ctx     = ssl_replace_hash(&s->write_hash, NULL);
            mac_ctx_sec = ssl_replace_hash(&s->write_hash_sec, NULL);
            if (mac_ctx == NULL || mac_ctx_sec == NULL)
                goto err;
        }

#ifndef OPENSSL_NO_COMP /*TODO_ Diversify this part */
        if (s->compress != NULL) {
            COMP_CTX_free(s->compress);
            s->compress = NULL;
        }
        if (comp != NULL) {
            s->compress = COMP_CTX_new(comp->method);
            if (s->compress == NULL) {
                SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE,
                       SSL_R_COMPRESSION_LIBRARY_ERROR);
                goto err2;
            }
        }
#endif
        /*
         * this is done by dtls1_reset_seq_numbers for DTLS
         */
        if (!SSL_IS_DTLS(s)){
            memset(&(s->s3->write_sequence[0]), 0, 8);
            memset(&(s->s3->write_sequence_sec[0]), 0, 8);
        }

        mac_secret = &(s->s3->write_mac_secret[0]);
        mac_secret_size = &(s->s3->write_mac_secret_size);

        mac_secret_sec = &(s->s3->write_mac_secret_sec[0]);
        mac_secret_size_sec = &(s->s3->write_mac_secret_size_sec);

    }

    if (reuse_dd)
        EVP_CIPHER_CTX_cleanup(dd);

    if (reuse_dd_sec)
    	EVP_CIPHER_CTX_cleanup(dd_sec);

    p = s->s3->tmp.key_block;
    i = *mac_secret_size = s->s3->tmp.new_mac_secret_size;
    cl = EVP_CIPHER_key_length(c);
    j = is_export ? (cl < SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher) ?
                     cl : SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher)) : cl;


    p_sec = s->s3->tmp.key_block_sec;
    ii = *mac_secret_size_sec = s->s3->tmp.new_mac_secret_size_sec;
    cl_sec = EVP_CIPHER_key_length(c_sec);
    jj = is_export_sec ? (cl_sec < SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher_sec) ?
                          cl_sec : SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher_sec)) : cl_sec;

    /* Was j=(exp)?5:EVP_CIPHER_key_length(c); */
    /* If GCM mode only part of IV comes from PRF */
    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
        k = EVP_GCM_TLS_FIXED_IV_LEN;
    else
        k = EVP_CIPHER_iv_length(c);

    /* VTTLS */
    /* Was j=(exp)?5:EVP_CIPHER_key_length(c); */
    /* If GCM mode only part of IV comes from PRF */
    if (EVP_CIPHER_mode(c_sec) == EVP_CIPH_GCM_MODE)
        k_sec = EVP_GCM_TLS_FIXED_IV_LEN;
    else
        k_sec = EVP_CIPHER_iv_length(c);

    // printf("[VTTLS] %s: k = %d; k_sec = %d\n", __func__, k, k_sec);

    if ((which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
        (which == SSL3_CHANGE_CIPHER_SERVER_READ)) {
        ms = &(p[0]);
        n = i + i;
        key = &(p[n]);
        n += j + j;
        iv = &(p[n]);
        n += k + k;
        exp_label = (unsigned char *)TLS_MD_CLIENT_WRITE_KEY_CONST;
        exp_label_len = TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE;
        client_write = 1;
    } else {
        n = i;
        ms = &(p[n]);
        n += i + j;
        key = &(p[n]);
        n += j + k;
        iv = &(p[n]);
        n += k;
        exp_label = (unsigned char *)TLS_MD_SERVER_WRITE_KEY_CONST;
        exp_label_len = TLS_MD_SERVER_WRITE_KEY_CONST_SIZE;
        client_write = 0;
    }

    /*
     * VTTLS-IMPLEMENTATION:
     * Second cipher IV
     *
     */

    if ((which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
        (which == SSL3_CHANGE_CIPHER_SERVER_READ)) {
        ms_sec = &(p_sec[0]);
        nn = ii + ii;
        key_sec = &(p_sec[nn]);
        nn += jj + jj;
        iv_sec = &(p_sec[nn]);
        nn += k_sec + k_sec;
        exp_label_sec = (unsigned char *)TLS_MD_CLIENT_WRITE_KEY_CONST;
        exp_label_len_sec = TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE;
        client_write = 1;
    } else {
        nn = ii;
        ms_sec = &(p_sec[nn]);
        nn += ii + jj;
        key_sec = &(p_sec[nn]);
        nn += jj + k_sec;
        iv_sec = &(p_sec[nn]);
        nn += k_sec;
        exp_label_sec = (unsigned char *)TLS_MD_SERVER_WRITE_KEY_CONST;
        exp_label_len_sec = TLS_MD_SERVER_WRITE_KEY_CONST_SIZE;
        client_write = 0;
    }

    /**************************************************/


    if (n > s->s3->tmp.key_block_length) {
        SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err2;
    }

    if (nn > s->s3->tmp.key_block_length_sec) {
        SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err2;
    }

    memcpy(mac_secret,     ms,     i);
    memcpy(mac_secret_sec, ms_sec, ii);

    if (!(EVP_CIPHER_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        mac_key = EVP_PKEY_new_mac_key(mac_type, NULL,
                                       mac_secret, *mac_secret_size);
        if (mac_key == NULL
                || EVP_DigestSignInit(mac_ctx, NULL, m, NULL, mac_key) <= 0) {
            EVP_PKEY_free(mac_key);
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        }
        EVP_PKEY_free(mac_key);
    }

    if (!(EVP_CIPHER_flags(c_sec) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        mac_key_sec = EVP_PKEY_new_mac_key(mac_type_sec, NULL,
                                       mac_secret_sec, *mac_secret_size_sec);
        if (mac_key_sec == NULL
                || EVP_DigestSignInit(mac_ctx_sec, NULL, m_sec, NULL, mac_key_sec) <= 0) {
            EVP_PKEY_free(mac_key_sec);
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        }
        EVP_PKEY_free(mac_key_sec);
    }

#ifdef TLS_DEBUG
    printf("which = %04X\nmac key=", which);
    {
        int z;
        for (z = 0; z < i; z++)
            printf("%02X%c", ms[z], ((z + 1) % 16) ? ' ' : '\n');
        for (z = 0; z < ii; z++)
            printf("%02X%c", ms_sec[z], ((z + 1) % 16) ? ' ' : '\n');
    }
#endif

	// printf("[VTTLS] %s: is_export? %d; is_export_sec? %d\n", __func__, is_export, is_export_sec);

    if (is_export) {
    	// printf("[VTTLS] %s: enc is export!!!\n", __func__);
        /*
         * In here I set both the read and write key/iv to the same value
         * since only the correct one will be used :-).
         */
        if (!tls1_PRF(ssl_get_algorithm2(s),
                      exp_label, exp_label_len,
                      s->s3->client_random, SSL3_RANDOM_SIZE,
                      s->s3->server_random, SSL3_RANDOM_SIZE,
                      NULL, 0, NULL, 0,
                      key, j, tmp1, tmp2, EVP_CIPHER_key_length(c)))
            goto err2;
        key = tmp1;

        if (k > 0) {
            if (!tls1_PRF(ssl_get_algorithm2(s),
                          TLS_MD_IV_BLOCK_CONST, TLS_MD_IV_BLOCK_CONST_SIZE,
                          s->s3->client_random, SSL3_RANDOM_SIZE,
                          s->s3->server_random, SSL3_RANDOM_SIZE,
                          NULL, 0, NULL, 0, empty, 0, iv1, iv2, k * 2))
                goto err2;
            if (client_write)
                iv = iv1;
            else
                iv = &(iv1[k]);
        }
    }

    /*  VTTLS TODO: Diversify
     *  I need a new function ssl_get_sec_algorithm2(s)
     *
     if (is_export_sec) {

        if (!tls1_PRF(ssl_get_sec_algorithm2(s),
                      exp_label_sec, exp_label_len_sec,
                      s->s3->client_random, SSL3_RANDOM_SIZE,
                      s->s3->server_random, SSL3_RANDOM_SIZE,
                      NULL, 0, NULL, 0,
                      key_sec, jj, tmp3, tmp4, EVP_CIPHER_key_length(c_sec)))
            goto err2;
        key_sec = tmp3;

        if (k_sec > 0) {
            if (!tls1_PRF(ssl_get_sec_algorithm2(s),
                          TLS_MD_IV_BLOCK_CONST, TLS_MD_IV_BLOCK_CONST_SIZE,
                          s->s3->client_random, SSL3_RANDOM_SIZE,
                          s->s3->server_random, SSL3_RANDOM_SIZE,
                          NULL, 0, NULL, 0, empty, 0, iv3, iv4, k_sec * 2))
                goto err2;
            if (client_write)
                iv = iv3;
            else
                iv = &(iv3[k_sec]);
        }
    } */

    s->session->key_arg_length = 0;

#ifdef KSSL_DEBUG
    {
        int i;
        fprintf(stderr, "EVP_CipherInit_ex(dd,c,key=,iv=,which)\n");
        fprintf(stderr, "\tkey= ");
        for (i = 0; i < c->key_len; i++)
            fprintf(stderr, "%02x", key[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "\t iv= ");
        for (i = 0; i < c->iv_len; i++)
            fprintf(stderr, "%02x", iv[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "\t iv_sec= ");
        for (i = 0; i < c_sec->iv_len; i++)
            fprintf(stderr, "%02x", iv_sec[i]);
        fprintf(stderr, "\n");
    }
#endif                          /* KSSL_DEBUG */

    /*
    if(c != NULL)
    	printf("[VTTLS] %s: EVP_CIPHER *c     = %s\n", __func__, OBJ_nid2ln(c->nid));
    if(c_sec != NULL)
        printf("[VTTLS] %s: EVP_CIPHER *c_sec = %s\n", __func__, OBJ_nid2ln(c_sec->nid));
     */

    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
        if (!EVP_CipherInit_ex(dd, c, NULL, key, NULL, (which & SSL3_CC_WRITE))
            || !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_GCM_SET_IV_FIXED, k, iv)) {
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        } else {
        	// printf("[VTTLS] %s: EVP_CIPHER c is using GCM.\n", __func__);
        }
    } else {
        if (!EVP_CipherInit_ex(dd, c, NULL, key, iv, (which & SSL3_CC_WRITE))) {
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        } else {
        	// printf("[VTTLS] %s: EVP_CIPHER c is NOT using GCM.\n", __func__);
        }
    }

    if (EVP_CIPHER_mode(c_sec) == EVP_CIPH_GCM_MODE) {
        if (!EVP_CipherInit_ex(dd_sec, c_sec, NULL, key_sec, NULL, (which & SSL3_CC_WRITE))
            || !EVP_CIPHER_CTX_ctrl(dd_sec, EVP_CTRL_GCM_SET_IV_FIXED, k_sec, iv_sec)) {
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        } else {
        	// printf("[VTTLS] %s: EVP_CIPHER c_sec is using GCM.\n", __func__);
        }
    } else {
        if (!EVP_CipherInit_ex(dd_sec, c_sec, NULL, key_sec, iv_sec, (which & SSL3_CC_WRITE))) {
            SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
            goto err2;
        } else {
        	// printf("[VTTLS] %s: EVP_CIPHER c_sec is NOT using GCM.\n", __func__);
        }
    }

    /* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
    if ((EVP_CIPHER_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER) && *mac_secret_size
        && !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_AEAD_SET_MAC_KEY,
                                *mac_secret_size, mac_secret)) {
        SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err2;
    }

    /* Duplicate the above for c_sec flags and so
     *
     * Needed for "composite" AEADs, such as RC4-HMAC-MD5*/
    if ((EVP_CIPHER_flags(c_sec) & EVP_CIPH_FLAG_AEAD_CIPHER) && *mac_secret_size_sec
        && !EVP_CIPHER_CTX_ctrl(dd_sec, EVP_CTRL_AEAD_SET_MAC_KEY,
                                *mac_secret_size_sec, mac_secret_sec)) {
        SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err2;
    }

#ifdef OPENSSL_SSL_TRACE_CRYPTO
    // printf("[VTTLS] %s: OPENSSL_SSL_TRACE_CRYPTO defined\n", __func__);
    if (s->msg_callback) {
        int wh = which & SSL3_CC_WRITE ? TLS1_RT_CRYPTO_WRITE : 0;
        if (*mac_secret_size)
            s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_MAC,
                            mac_secret, *mac_secret_size,
                            s, s->msg_callback_arg);
        if (c->key_len)
            s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_KEY,
                            key, c->key_len, s, s->msg_callback_arg);
        if (k) {
            if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
                wh |= TLS1_RT_CRYPTO_FIXED_IV;
            else
                wh |= TLS1_RT_CRYPTO_IV;
            s->msg_callback(2, s->version, wh, iv, k, s, s->msg_callback_arg);
        }

        /* TODO: Duplicate the above for k_sec? */
    }
#endif

#ifdef TLS_DEBUG
    printf("which = %04X\nkey=", which);
    {
        int z;
        for (z = 0; z < EVP_CIPHER_key_length(c); z++)
            printf("%02X%c", key[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\niv=");
    {
        int z;
        for (z = 0; z < k; z++)
            printf("%02X%c", iv[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\n");
#endif

    OPENSSL_cleanse(tmp1, sizeof(tmp1));
    OPENSSL_cleanse(tmp2, sizeof(tmp1));

    OPENSSL_cleanse(iv1, sizeof(iv1));
    OPENSSL_cleanse(iv2, sizeof(iv2));

    OPENSSL_cleanse(iv3, sizeof(iv3));
    OPENSSL_cleanse(iv4, sizeof(iv4));
    return (1);
 err:
    SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
 err2:
    return (0);
}

int tls1_setup_key_block(SSL *s)
{
    unsigned char *p1, *p2 = NULL;
    unsigned char *p3, *p4 = NULL;
    const EVP_CIPHER *c, *c_sec;
    const EVP_MD *hash, *hash_sec;
    int num, num_sec;
    SSL_COMP *comp, *comp_sec;
    int mac_type = NID_undef, mac_type_sec = NID_undef, mac_secret_size = 0, mac_secret_size_sec = 0;
    int ret = 0;

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_setup_key_block()\n");
#endif                          /* KSSL_DEBUG */

    if (s->s3->tmp.key_block_length != 0)
        return (1);

    /* VTTLS: DEBUGGING PURPOSES */

    /* if( s->session->cipher != NULL )
		printf("[VTTLS] %s: SESSION->cipher -- %s\n", __func__, s->session->cipher->name);
	else
		printf("[VTTLS] %s: SESSION->cipher -- NULL\n", __func__);

    if( s->session->secondary_cipher != NULL )
		printf("[VTTLS] %s: SESSION->sec_cipher -- %s\n", __func__, s->session->secondary_cipher->name);
	else
		printf("[VTTLS] %s: SESSION->sec_cipher -- NULL\n", __func__); */
    /* ************************* */

    if (!ssl_cipher_get_evp
        (s->session, &c, &hash, &mac_type, &mac_secret_size, &comp)) {
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return (0);
    }

    if (!ssl_secondary_cipher_get_evp
        (s->session, &c_sec, &hash_sec, &mac_type_sec, &mac_secret_size_sec, &comp_sec)) {
    	// printf("[VTTLS] %s: 'ssl_secondary_cipher_get_evp' not working\n", __func__);
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return (0);
    }

    s->s3->tmp.new_sym_enc = c;
    /* VTTLS: Keeping the secondary EVP_CIPHER */
    s->s3->tmp.new_sec_sym_enc = c_sec;

    s->s3->tmp.new_hash = hash;
    s->s3->tmp.new_mac_pkey_type = mac_type;
    s->s3->tmp.new_mac_secret_size = mac_secret_size;
    num =
        EVP_CIPHER_key_length(c) + mac_secret_size + EVP_CIPHER_iv_length(c);
    num *= 2;

    /* Keep the secondary cipher hash, mac_pkey_type and mac_secret_size */
    s->s3->tmp.new_hash_sec = hash_sec;
    s->s3->tmp.new_mac_pkey_type_sec = mac_type_sec;
    s->s3->tmp.new_mac_secret_size_sec = mac_secret_size_sec;
    num_sec =
        EVP_CIPHER_key_length(c_sec) + mac_secret_size_sec + EVP_CIPHER_iv_length(c_sec);
    num_sec *= 2;

    ssl3_cleanup_key_block(s);

    if ((p1 = (unsigned char *)OPENSSL_malloc(num)) == NULL) {
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((p3 = (unsigned char *)OPENSSL_malloc(num_sec)) == NULL) {
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    s->s3->tmp.key_block_length = num;
    s->s3->tmp.key_block = p1;

    s->s3->tmp.key_block_length_sec = num_sec;
    s->s3->tmp.key_block_sec = p3;

    if ((p2 = (unsigned char *)OPENSSL_malloc(num)) == NULL) {
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(p1);
        goto err;
    }

    if ((p4 = (unsigned char *)OPENSSL_malloc(num_sec)) == NULL) {
        SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(p3);
        goto err;
    }

#ifdef TLS_DEBUG
    printf("client random\n");
    {
        int z;
        for (z = 0; z < SSL3_RANDOM_SIZE; z++)
            printf("%02X%c", s->s3->client_random[z],
                   ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("server random\n");
    {
        int z;
        for (z = 0; z < SSL3_RANDOM_SIZE; z++)
            printf("%02X%c", s->s3->server_random[z],
                   ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("pre-master\n");
    {
        int z;
        for (z = 0; z < s->session->master_key_length; z++)
            printf("%02X%c", s->session->master_key[z],
                   ((z + 1) % 16) ? ' ' : '\n');
    }
#endif

    if (!tls1_generate_key_block(s, p1, p2, num))
        goto err;

    if (!tls1_generate_key_block(s, p3, p4, num_sec))
        goto err;

#ifdef TLS_DEBUG
    printf("\nkey block\n");
    {
        int z;
        for (z = 0; z < num; z++)
            printf("%02X%c", p1[z], ((z + 1) % 16) ? ' ' : '\n');
    }
#endif

    if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        && s->method->version <= TLS1_VERSION) {
        /*
         * enable vulnerability countermeasure for CBC ciphers with known-IV
         * problem (http://www.openssl.org/~bodo/tls-cbc.txt)
         */
        s->s3->need_empty_fragments = 1;

        if (s->session->cipher != NULL) {
            if (s->session->cipher->algorithm_enc == SSL_eNULL)
                s->s3->need_empty_fragments = 0;

#ifndef OPENSSL_NO_RC4
            if (s->session->cipher->algorithm_enc == SSL_RC4)
                s->s3->need_empty_fragments = 0;
#endif
        }
    }

    ret = 1;
 err:
    if (p2) {
        OPENSSL_cleanse(p2, num);
        OPENSSL_free(p2);
    }
    if (p4) {
        OPENSSL_cleanse(p4, num_sec);
        OPENSSL_free(p4);
    }
    return (ret);
}

/*-
 * tls1_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding/AEAD-authenticator is invalid or, if sending,
 *       an internal error occured.
 */
int tls1_enc(SSL *s, int send)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, j, k, pad = 0, ret, mac_size = 0;
    const EVP_CIPHER *enc;

    unsigned long ui;

    if (send) {

        if (EVP_MD_CTX_md(s->write_hash)) {
            int n = EVP_MD_CTX_size(s->write_hash);
            OPENSSL_assert(n >= 0);
        }

        ds = s->enc_write_ctx;
        rec = &(s->s3->wrec);

        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else {

            int ivlen;
            enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);

            /* For TLSv1.1 and later explicit IV */
            if (SSL_USE_EXPLICIT_IV(s)
                && EVP_CIPHER_mode(enc) == EVP_CIPH_CBC_MODE)
                ivlen = EVP_CIPHER_iv_length(enc);
            else
                ivlen = 0;

            if (ivlen > 1) {
                if (rec->data != rec->input)
                    fprintf(stderr,
                            "%s:%d: rec->data != rec->input\n",
                            __FILE__, __LINE__);
                else if (RAND_bytes(rec->input, ivlen) <= 0)
                    return -1;
            }
        }

    } else {

        if (EVP_MD_CTX_md(s->read_hash)) {
            int n = EVP_MD_CTX_size(s->read_hash);
            OPENSSL_assert(n >= 0);
        }

        ds = s->enc_read_ctx;
        rec = &(s->s3->rrec);

        if (s->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);

    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        ret = 1;
    } else {
        l = rec->length;
        bs = EVP_CIPHER_block_size(ds->cipher);

        if (EVP_CIPHER_flags(ds->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
            unsigned char buf[EVP_AEAD_TLS1_AAD_LEN], *seq;

            seq = send ? s->s3->write_sequence : s->s3->read_sequence;

            if (SSL_IS_DTLS(s)) {
                unsigned char dtlsseq[9], *p = dtlsseq;

                s2n(send ? s->d1->w_epoch : s->d1->r_epoch, p);
                memcpy(p, &seq[2], 6);
                memcpy(buf, dtlsseq, 8);
            } else {
                memcpy(buf, seq, 8);
                for (i = 7; i >= 0; i--) { /* increment */
                    ++seq[i];
                    if (seq[i] != 0)
                        break;
                }
            }

            buf[8] = rec->type;
            buf[9] = (unsigned char)(s->version >> 8);
            buf[10] = (unsigned char)(s->version);
            buf[11] = rec->length >> 8;
            buf[12] = rec->length & 0xff;
            pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                                      EVP_AEAD_TLS1_AAD_LEN, buf);

            if (pad <= 0)
                return -1;
            if (send) {
                l += pad;
                rec->length += pad;
            }
        } else if ((bs != 1) && send) {
            i = bs - ((int)l % bs);

            /* Add weird padding of upto 256 bytes */

            /* we need to add 'i' padding bytes of value j */
            j = i - 1;
            if (s->options & SSL_OP_TLS_BLOCK_PADDING_BUG) {
                if (s->s3->flags & TLS1_FLAGS_TLS_PADDING_BUG)
                    j++;
            }
            for (k = (int)l; k < (int)(l + i); k++)
                rec->input[k] = j;
            l += i;
            rec->length += i;
        }

#ifdef KSSL_DEBUG
        {
            unsigned long ui;
            fprintf(stderr,
                    "EVP_Cipher(ds=%p,rec->data=%p,rec->input=%p,l=%ld) ==>\n",
                    ds, rec->data, rec->input, l);
            fprintf(stderr, "IV_len: %d; IV_len_sec: %d\n",
            		ds->cipher->iv_len, ds_sec->cipher->iv_len);
            fprintf(stderr, "\t\tIV:     ");
            for (i = 0; i < ds->cipher->iv_len; i++)
                fprintf(stderr, " %02X", ds->iv[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "\t\tIV_SEC: ");
            for (i = 0; i < ds_sec->cipher->iv_len; i++)
                fprintf(stderr, " %02X", ds_sec->iv[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "\trec->input=");
            for (ui = 0; ui < l; ui++)
                fprintf(stderr, " %02x", rec->input[ui]);
            fprintf(stderr, "\n");
        }
#endif                          /* KSSL_DEBUG */

        if (!send) {
            if (l == 0 || l % bs != 0){
                return 0;
            }
        }

        i = EVP_Cipher(ds, rec->data, rec->input, l);

        if ((EVP_CIPHER_flags(ds->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER)
            ? (i < 0)
            : (i == 0))
            return -1;          /* AEAD can fail to verify MAC */

        if (EVP_CIPHER_mode(enc) == EVP_CIPH_GCM_MODE && !send) {
            rec->data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            rec->input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            rec->length -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
        }

#ifdef KSSL_DEBUG
        {
            unsigned long i;
            fprintf(stderr, "\trec->data=");
            for (i = 0; i < l; i++)
                fprintf(stderr, " %02x", rec->data[i]);
            fprintf(stderr, "\n");
        }
#endif                          /* KSSL_DEBUG */

        ret = 1;
        if (EVP_MD_CTX_md(s->read_hash) != NULL)
            mac_size = EVP_MD_CTX_size(s->read_hash);

        if ((bs != 1) && !send){
            ret = tls1_cbc_remove_padding(s, rec, bs, mac_size);
        }

        if (pad && !send)
            rec->length -= pad;
    }

    return ret;
}

int tls1_sec_enc(SSL *s, int send){

    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, j, k, pad = 0, ret, mac_size = 0;
    const EVP_CIPHER *enc;

    EVP_CIPHER_CTX *ds_sec;
    int bs_sec, ii, mac_size_sec = 0;
    const EVP_CIPHER *enc_sec;

	unsigned long ui;

    if (send) {

        if (EVP_MD_CTX_md(s->write_hash_sec)) {
            int n = EVP_MD_CTX_size(s->write_hash_sec);
            OPENSSL_assert(n >= 0);
        }

        ds_sec = s->sec_enc_write_ctx;
        rec = &(s->s3->wrec);

        if(s->sec_enc_write_ctx == NULL)
            enc_sec = NULL;
        else {

        	int ivlen_sec;
            enc_sec = EVP_CIPHER_CTX_cipher(s->sec_enc_write_ctx);

            /* For TLSv1.1 and later explicit IV */
            if (SSL_USE_EXPLICIT_IV(s)
                && EVP_CIPHER_mode(enc_sec) == EVP_CIPH_CBC_MODE)
                ivlen_sec = EVP_CIPHER_iv_length(enc_sec);
            else
                ivlen_sec = 0;

            if (ivlen_sec > 1) {
                if (rec->data != rec->input)
                    fprintf(stderr,
                            "%s:%d: rec->data != rec->input\n",
                            __FILE__, __LINE__);
                else if (RAND_bytes(rec->input, ivlen_sec) <= 0)
                    return -1;
            }

        }

    } else {

        if (EVP_MD_CTX_md(s->read_hash_sec)) {
            int n = EVP_MD_CTX_size(s->read_hash_sec);
            OPENSSL_assert(n >= 0);
        }

        ds_sec = s->sec_enc_read_ctx;
        rec = &(s->s3->rrec);

        if (s->sec_enc_read_ctx == NULL)
        	enc_sec = NULL;
        else
        	/* VTTLS: Getting the secondary cipher from the EVP_CIPHER_CTX */
            enc_sec = EVP_CIPHER_CTX_cipher(s->sec_enc_read_ctx);

    }

    if ((s->session == NULL) || (ds_sec == NULL) || (enc_sec == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        ret = 1;
    } else {
        l = rec->length;
        bs_sec = EVP_CIPHER_block_size(ds_sec->cipher);

        if (EVP_CIPHER_flags(ds_sec->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
            unsigned char buf[EVP_AEAD_TLS1_AAD_LEN], *seq;

            seq = send ? s->s3->write_sequence_sec : s->s3->read_sequence_sec;

            if (SSL_IS_DTLS(s)) {
                unsigned char dtlsseq[9], *p = dtlsseq;

                s2n(send ? s->d1->w_epoch : s->d1->r_epoch, p);
                memcpy(p, &seq[2], 6);
                memcpy(buf, dtlsseq, 8);
            } else {
                memcpy(buf, seq, 8);
                for (i = 7; i >= 0; i--) { /* increment */
                    ++seq[i];
                    if (seq[i] != 0)
                        break;
                }
            }

            buf[8] = rec->type; // Probably dont need this for sec_enc
            buf[9] = (unsigned char)(s->version >> 8); // Probably dont need this for sec_enc
            buf[10] = (unsigned char)(s->version); // Probably dont need this for sec_enc
            buf[11] = rec->length >> 8;
            buf[12] = rec->length & 0xff;
            pad = EVP_CIPHER_CTX_ctrl(ds_sec, EVP_CTRL_AEAD_TLS1_AAD,
                                      EVP_AEAD_TLS1_AAD_LEN, buf);

            if (pad <= 0)
                return -1;
            if (send) {
                l += pad;
                rec->length += pad;
            }
        } else if ((bs_sec != 1) && send) {
            i = bs_sec - ((int)l % bs_sec);

            /* Add weird padding of upto 256 bytes */

            /* we need to add 'i' padding bytes of value j */
            j = i - 1;
            if (s->options & SSL_OP_TLS_BLOCK_PADDING_BUG) {
                if (s->s3->flags & TLS1_FLAGS_TLS_PADDING_BUG)
                    j++;
            }
            for (k = (int)l; k < (int)(l + i); k++)
                rec->input[k] = j;
            l += i;
            rec->length += i;
        }

#ifdef KSSL_DEBUG
        {
            unsigned long ui;
            fprintf(stderr,
                    "EVP_Cipher(ds=%p,rec->data=%p,rec->input=%p,l=%ld) ==>\n",
                    ds, rec->data, rec->input, l);
            fprintf(stderr, "IV_len: %d; IV_len_sec: %d\n",
            		ds->cipher->iv_len, ds_sec->cipher->iv_len);
            fprintf(stderr, "\t\tIV:     ");
            for (i = 0; i < ds->cipher->iv_len; i++)
                fprintf(stderr, " %02X", ds->iv[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "\t\tIV_SEC: ");
            for (i = 0; i < ds_sec->cipher->iv_len; i++)
                fprintf(stderr, " %02X", ds_sec->iv[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "\trec->input=");
            for (ui = 0; ui < l; ui++)
                fprintf(stderr, " %02x", rec->input[ui]);
            fprintf(stderr, "\n");
        }
#endif                          /* KSSL_DEBUG */

        if (!send) {
            if (l == 0 || l % bs_sec != 0){
                return 0;
            }
        }

        i = EVP_Cipher(ds_sec, rec->data, rec->input, l);

        if ((EVP_CIPHER_flags(ds_sec->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER)
            ? (i < 0)
            : (i == 0))
            return -1;          /* AEAD can fail to verify MAC */

        if (EVP_CIPHER_mode(enc_sec) == EVP_CIPH_GCM_MODE && !send) {
            rec->data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            rec->input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            rec->length -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
        }

        ret = 1;

        if (EVP_MD_CTX_md(s->read_hash_sec) != NULL)
            mac_size_sec = EVP_MD_CTX_size(s->read_hash_sec);

        if ((bs_sec != 1) && !send){
            ret = tls1_cbc_remove_padding(s, rec, bs_sec, mac_size_sec);
        }

        if (pad && !send)
            rec->length -= pad;
    }

    return ret;

}

int tls1_cert_verify_mac(SSL *s, int md_nid, unsigned char *out)
{
    unsigned int ret;
    EVP_MD_CTX ctx, *d = NULL;
    int i;

    if (s->s3->handshake_buffer)
        if (!ssl3_digest_cached_records(s))
            return 0;

    for (i = 0; i < SSL_MAX_DIGEST; i++) {
        if (s->s3->handshake_dgst[i]
            && EVP_MD_CTX_type(s->s3->handshake_dgst[i]) == md_nid) {
            d = s->s3->handshake_dgst[i];
            break;
        }
    }
    if (!d) {
        SSLerr(SSL_F_TLS1_CERT_VERIFY_MAC, SSL_R_NO_REQUIRED_DIGEST);
        return 0;
    }

    EVP_MD_CTX_init(&ctx);
    if (EVP_MD_CTX_copy_ex(&ctx, d) <=0
            || EVP_DigestFinal_ex(&ctx, out, &ret) <= 0)
        ret = 0;
    EVP_MD_CTX_cleanup(&ctx);
    return ((int)ret);
}

int tls1_final_finish_mac(SSL *s,
                          const char *str, int slen, unsigned char *out)
{
    unsigned int i;
    EVP_MD_CTX ctx;
    unsigned char buf[2 * EVP_MAX_MD_SIZE];
    unsigned char *q, buf2[12];
    int idx;
    long mask;
    int err = 0;
    const EVP_MD *md;

    q = buf;

    if (s->s3->handshake_buffer)
        if (!ssl3_digest_cached_records(s))
            return 0;

    EVP_MD_CTX_init(&ctx);

    for (idx = 0; ssl_get_handshake_digest(idx, &mask, &md); idx++) {
        if (mask & ssl_get_algorithm2(s)) {
            int hashsize = EVP_MD_size(md);
            EVP_MD_CTX *hdgst = s->s3->handshake_dgst[idx];
            if (!hdgst || hashsize < 0
                || hashsize > (int)(sizeof buf - (size_t)(q - buf))) {
                /*
                 * internal error: 'buf' is too small for this cipersuite!
                 */
                err = 1;
            } else {
                if (!EVP_MD_CTX_copy_ex(&ctx, hdgst) ||
                    !EVP_DigestFinal_ex(&ctx, q, &i) ||
                    (i != (unsigned int)hashsize))
                    err = 1;
                q += hashsize;
            }
        }
    }

    if (!tls1_PRF(ssl_get_algorithm2(s),
                  str, slen, buf, (int)(q - buf), NULL, 0, NULL, 0, NULL, 0,
                  s->session->master_key, s->session->master_key_length,
                  out, buf2, sizeof buf2))
        err = 1;
    EVP_MD_CTX_cleanup(&ctx);

    OPENSSL_cleanse(buf, (int)(q - buf));
    OPENSSL_cleanse(buf2, sizeof(buf2));
    if (err)
        return 0;
    else
        return sizeof buf2;
}

int tls1_mac(SSL *ssl, unsigned char *md, int send)
{
    SSL3_RECORD *rec;
    unsigned char *seq;
    EVP_MD_CTX *hash;
    size_t md_size, orig_len;
    int i;
    EVP_MD_CTX hmac, *mac_ctx;
    unsigned char header[13];
    int stream_mac = (send ? (ssl->mac_flags & SSL_MAC_FLAG_WRITE_MAC_STREAM)
                           : (ssl->mac_flags & SSL_MAC_FLAG_READ_MAC_STREAM));
    int t;

    if (send) {
        rec = &(ssl->s3->wrec);
        seq = &(ssl->s3->write_sequence[0]);
        hash = ssl->write_hash;
    } else {
        rec = &(ssl->s3->rrec);
        seq = &(ssl->s3->read_sequence[0]);
        hash = ssl->read_hash;
    }

    t = EVP_MD_CTX_size(hash);
    OPENSSL_assert(t >= 0);
    md_size = t;

    /* I should fix this up TLS TLS TLS TLS TLS XXXXXXXX */
    if (stream_mac) {
        mac_ctx = hash;
    } else {
        if (!EVP_MD_CTX_copy(&hmac, hash))
            return -1;
        mac_ctx = &hmac;
    }

    if (SSL_IS_DTLS(ssl)) {
        unsigned char dtlsseq[8], *p = dtlsseq;

        s2n(send ? ssl->d1->w_epoch : ssl->d1->r_epoch, p);
        memcpy(p, &seq[2], 6);

        memcpy(header, dtlsseq, 8);
    } else
        memcpy(header, seq, 8);

    /*
     * kludge: tls1_cbc_remove_padding passes padding length in rec->type
     */
    orig_len = rec->length + md_size + ((unsigned int)rec->type >> 8);
    rec->type &= 0xff;

    header[8] = rec->type;
    header[9] = (unsigned char)(ssl->version >> 8);
    header[10] = (unsigned char)(ssl->version);
    header[11] = (rec->length) >> 8;
    header[12] = (rec->length) & 0xff;

    if (!send &&
        EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
        ssl3_cbc_record_digest_supported(mac_ctx)) {
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */
        /* Final param == not SSLv3 */
        if (ssl3_cbc_digest_record(mac_ctx,
                                   md, &md_size,
                                   header, rec->input,
                                   rec->length + md_size, orig_len,
                                   ssl->s3->read_mac_secret,
                                   ssl->s3->read_mac_secret_size, 0) <= 0) {
            if (!stream_mac)
                EVP_MD_CTX_cleanup(&hmac);
            return -1;
        }
    } else {
        if (EVP_DigestSignUpdate(mac_ctx, header, sizeof(header)) <= 0
                || EVP_DigestSignUpdate(mac_ctx, rec->input, rec->length) <= 0
                || EVP_DigestSignFinal(mac_ctx, md, &md_size) <= 0) {
            if (!stream_mac)
                EVP_MD_CTX_cleanup(&hmac);
            return -1;
        }
#ifdef OPENSSL_FIPS
        if (!send && FIPS_mode())
            tls_fips_digest_extra(ssl->enc_read_ctx,
                                  mac_ctx, rec->input, rec->length, orig_len);
#endif
    }

    if (!stream_mac)
        EVP_MD_CTX_cleanup(&hmac);
#ifdef TLS_DEBUG
    fprintf(stderr, "seq=");
    {
        int z;
        for (z = 0; z < 8; z++)
            fprintf(stderr, "%02X ", seq[z]);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "rec=");
    {
        unsigned int z;
        for (z = 0; z < rec->length; z++)
            fprintf(stderr, "%02X ", rec->data[z]);
        fprintf(stderr, "\n");
    }
#endif

    if (!SSL_IS_DTLS(ssl)) {
        for (i = 7; i >= 0; i--) {
            ++seq[i];
            if (seq[i] != 0)
                break;
        }
    }
#ifdef TLS_DEBUG
    {
        unsigned int z;
        for (z = 0; z < md_size; z++)
            fprintf(stderr, "%02X ", md[z]);
        fprintf(stderr, "\n");
    }
#endif
    return (md_size);
}

int tls1_sec_mac(SSL *ssl, unsigned char *md, int send)
{
    SSL3_RECORD *rec;
    unsigned char *seq;
    EVP_MD_CTX *hash_sec;
    size_t md_size_sec, orig_len;
    int i;
    EVP_MD_CTX hmac_sec, *mac_ctx_sec;
    unsigned char header[13];
    int stream_mac_sec = (send ? (ssl->mac_flags_sec & SSL_MAC_FLAG_WRITE_MAC_STREAM)
                               : (ssl->mac_flags_sec & SSL_MAC_FLAG_READ_MAC_STREAM));
    int t;

    if (send) {
        rec = &(ssl->s3->wrec);
        seq = &(ssl->s3->write_sequence_sec[0]);
        hash_sec = ssl->write_hash_sec;
    } else {
        rec = &(ssl->s3->rrec);
        seq = &(ssl->s3->read_sequence_sec[0]);
        hash_sec = ssl->read_hash_sec;
    }

    t = EVP_MD_CTX_size(hash_sec);
    OPENSSL_assert(t >= 0);
    md_size_sec = t;

    /* I should fix this up TLS TLS TLS TLS TLS XXXXXXXX */
    if (stream_mac_sec) {
    	mac_ctx_sec = hash_sec;
    } else {
        if (!EVP_MD_CTX_copy(&hmac_sec, hash_sec))
            return -1;
        mac_ctx_sec = &hmac_sec;
    }

    if (SSL_IS_DTLS(ssl)) {
        unsigned char dtlsseq[8], *p = dtlsseq;

        s2n(send ? ssl->d1->w_epoch : ssl->d1->r_epoch, p);
        memcpy(p, &seq[2], 6);

        memcpy(header, dtlsseq, 8);
    } else
        memcpy(header, seq, 8);

    /*
     * kludge: tls1_cbc_remove_padding passes padding length in rec->type
     */
    orig_len = rec->length + md_size_sec + ((unsigned int)rec->type >> 8);
    rec->type &= 0xff;

    header[8] = rec->type;
    header[9] = (unsigned char)(ssl->version >> 8);
    header[10] = (unsigned char)(ssl->version);
    header[11] = (rec->length) >> 8;
    header[12] = (rec->length) & 0xff;

    if (!send &&
        EVP_CIPHER_CTX_mode(ssl->sec_enc_read_ctx) == EVP_CIPH_CBC_MODE &&
        ssl3_cbc_record_digest_supported(mac_ctx_sec)) {
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */
        /* Final param == not SSLv3 */
        if (ssl3_cbc_digest_record(mac_ctx_sec,
                                   md, &md_size_sec,
                                   header, rec->input,
                                   rec->length + md_size_sec, orig_len,
                                   ssl->s3->read_mac_secret_sec,
                                   ssl->s3->read_mac_secret_size_sec, 0) <= 0) {
            if (!stream_mac_sec)
                EVP_MD_CTX_cleanup(&hmac_sec);
            return -1;
        }
    } else {
        if (EVP_DigestSignUpdate(mac_ctx_sec, header, sizeof(header)) <= 0
                || EVP_DigestSignUpdate(mac_ctx_sec, rec->input, rec->length) <= 0
                || EVP_DigestSignFinal(mac_ctx_sec, md, &md_size_sec) <= 0) {
            if (!stream_mac_sec)
                EVP_MD_CTX_cleanup(&hmac_sec);
            return -1;
        }
#ifdef OPENSSL_FIPS
        if (!send && FIPS_mode())
            tls_fips_digest_extra(ssl->sec_enc_read_ctx,
                                  mac_ctx_sec, rec->input, rec->length, orig_len);
#endif
    }

    if (!stream_mac_sec)
        EVP_MD_CTX_cleanup(&hmac_sec);
#ifdef TLS_DEBUG
    fprintf(stderr, "seq=");
    {
        int z;
        for (z = 0; z < 8; z++)
            fprintf(stderr, "%02X ", seq[z]);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "rec=");
    {
        unsigned int z;
        for (z = 0; z < rec->length; z++)
            fprintf(stderr, "%02X ", rec->data[z]);
        fprintf(stderr, "\n");
    }
#endif

    if (!SSL_IS_DTLS(ssl)) {
        for (i = 7; i >= 0; i--) {
            ++seq[i];
            if (seq[i] != 0)
                break;
        }
    }
#ifdef TLS_DEBUG
    {
        unsigned int z;
        for (z = 0; z < md_size_sec; z++)
            fprintf(stderr, "%02X ", md[z]);
        fprintf(stderr, "\n");
    }
#endif
    return (md_size_sec);
}

int tls1_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p,
                                int len)
{
    unsigned char buff[SSL_MAX_MASTER_KEY_LENGTH];
    const void *co = NULL, *so = NULL;
    int col = 0, sol = 0;

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_generate_master_secret(%p,%p, %p, %d)\n", s, out, p,
            len);
#endif                          /* KSSL_DEBUG */

#ifdef TLSEXT_TYPE_opaque_prf_input
    if (s->s3->client_opaque_prf_input != NULL
        && s->s3->server_opaque_prf_input != NULL
        && s->s3->client_opaque_prf_input_len > 0
        && s->s3->client_opaque_prf_input_len ==
        s->s3->server_opaque_prf_input_len) {
        co = s->s3->client_opaque_prf_input;
        col = s->s3->server_opaque_prf_input_len;
        so = s->s3->server_opaque_prf_input;
        /*
         * must be same as col (see
         * draft-rescorla-tls-opaque-prf-input-00.txt, section 3.1)
         */
        sol = s->s3->client_opaque_prf_input_len;
    }
#endif

    tls1_PRF(ssl_get_algorithm2(s),
             TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
             s->s3->client_random, SSL3_RANDOM_SIZE,
             co, col,
             s->s3->server_random, SSL3_RANDOM_SIZE,
             so, sol, p, len, s->session->master_key, buff, sizeof buff);
    OPENSSL_cleanse(buff, sizeof buff);
#ifdef SSL_DEBUG
    fprintf(stderr, "Premaster Secret:\n");
    BIO_dump_fp(stderr, (char *)p, len);
    fprintf(stderr, "Client Random:\n");
    BIO_dump_fp(stderr, (char *)s->s3->client_random, SSL3_RANDOM_SIZE);
    fprintf(stderr, "Server Random:\n");
    BIO_dump_fp(stderr, (char *)s->s3->server_random, SSL3_RANDOM_SIZE);
    fprintf(stderr, "Master Secret:\n");
    BIO_dump_fp(stderr, (char *)s->session->master_key,
                SSL3_MASTER_SECRET_SIZE);
#endif

#ifdef OPENSSL_SSL_TRACE_CRYPTO
    if (s->msg_callback) {
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_PREMASTER,
                        p, len, s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_CLIENT_RANDOM,
                        s->s3->client_random, SSL3_RANDOM_SIZE,
                        s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_SERVER_RANDOM,
                        s->s3->server_random, SSL3_RANDOM_SIZE,
                        s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_MASTER,
                        s->session->master_key,
                        SSL3_MASTER_SECRET_SIZE, s, s->msg_callback_arg);
    }
#endif

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_generate_master_secret() complete\n");
#endif                          /* KSSL_DEBUG */
    return (SSL3_MASTER_SECRET_SIZE);
}

int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                const char *label, size_t llen,
                                const unsigned char *context,
                                size_t contextlen, int use_context)
{
    unsigned char *buff;
    unsigned char *val = NULL;
    size_t vallen, currentvalpos;
    int rv;

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_export_keying_material(%p,%p,%lu,%s,%lu,%p,%lu)\n",
            s, out, olen, label, llen, context, contextlen);
#endif                          /* KSSL_DEBUG */

    buff = OPENSSL_malloc(olen);
    if (buff == NULL)
        goto err2;

    /*
     * construct PRF arguments we construct the PRF argument ourself rather
     * than passing separate values into the TLS PRF to ensure that the
     * concatenation of values does not create a prohibited label.
     */
    vallen = llen + SSL3_RANDOM_SIZE * 2;
    if (use_context) {
        vallen += 2 + contextlen;
    }

    val = OPENSSL_malloc(vallen);
    if (val == NULL)
        goto err2;
    currentvalpos = 0;
    memcpy(val + currentvalpos, (unsigned char *)label, llen);
    currentvalpos += llen;
    memcpy(val + currentvalpos, s->s3->client_random, SSL3_RANDOM_SIZE);
    currentvalpos += SSL3_RANDOM_SIZE;
    memcpy(val + currentvalpos, s->s3->server_random, SSL3_RANDOM_SIZE);
    currentvalpos += SSL3_RANDOM_SIZE;

    if (use_context) {
        val[currentvalpos] = (contextlen >> 8) & 0xff;
        currentvalpos++;
        val[currentvalpos] = contextlen & 0xff;
        currentvalpos++;
        if ((contextlen > 0) || (context != NULL)) {
            memcpy(val + currentvalpos, context, contextlen);
        }
    }

    /*
     * disallow prohibited labels note that SSL3_RANDOM_SIZE > max(prohibited
     * label len) = 15, so size of val > max(prohibited label len) = 15 and
     * the comparisons won't have buffer overflow
     */
    if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
               TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
               TLS_MD_SERVER_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
               TLS_MD_MASTER_SECRET_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
               TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0)
        goto err1;

    rv = tls1_PRF(ssl_get_algorithm2(s),
                  val, vallen,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  s->session->master_key, s->session->master_key_length,
                  out, buff, olen);
    OPENSSL_cleanse(val, vallen);
    OPENSSL_cleanse(buff, olen);

#ifdef KSSL_DEBUG
    fprintf(stderr, "tls1_export_keying_material() complete\n");
#endif                          /* KSSL_DEBUG */
    goto ret;
 err1:
    SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL,
           SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
    rv = 0;
    goto ret;
 err2:
    SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL, ERR_R_MALLOC_FAILURE);
    rv = 0;
 ret:
    if (buff != NULL)
        OPENSSL_free(buff);
    if (val != NULL)
        OPENSSL_free(val);
    return (rv);
}

int tls1_alert_code(int code)
{
    switch (code) {
    case SSL_AD_CLOSE_NOTIFY:
        return (SSL3_AD_CLOSE_NOTIFY);
    case SSL_AD_UNEXPECTED_MESSAGE:
        return (SSL3_AD_UNEXPECTED_MESSAGE);
    case SSL_AD_BAD_RECORD_MAC:
        return (SSL3_AD_BAD_RECORD_MAC);
    case SSL_AD_DECRYPTION_FAILED:
        return (TLS1_AD_DECRYPTION_FAILED);
    case SSL_AD_RECORD_OVERFLOW:
        return (TLS1_AD_RECORD_OVERFLOW);
    case SSL_AD_DECOMPRESSION_FAILURE:
        return (SSL3_AD_DECOMPRESSION_FAILURE);
    case SSL_AD_HANDSHAKE_FAILURE:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_NO_CERTIFICATE:
        return (-1);
    case SSL_AD_BAD_CERTIFICATE:
        return (SSL3_AD_BAD_CERTIFICATE);
    case SSL_AD_UNSUPPORTED_CERTIFICATE:
        return (SSL3_AD_UNSUPPORTED_CERTIFICATE);
    case SSL_AD_CERTIFICATE_REVOKED:
        return (SSL3_AD_CERTIFICATE_REVOKED);
    case SSL_AD_CERTIFICATE_EXPIRED:
        return (SSL3_AD_CERTIFICATE_EXPIRED);
    case SSL_AD_CERTIFICATE_UNKNOWN:
        return (SSL3_AD_CERTIFICATE_UNKNOWN);
    case SSL_AD_ILLEGAL_PARAMETER:
        return (SSL3_AD_ILLEGAL_PARAMETER);
    case SSL_AD_UNKNOWN_CA:
        return (TLS1_AD_UNKNOWN_CA);
    case SSL_AD_ACCESS_DENIED:
        return (TLS1_AD_ACCESS_DENIED);
    case SSL_AD_DECODE_ERROR:
        return (TLS1_AD_DECODE_ERROR);
    case SSL_AD_DECRYPT_ERROR:
        return (TLS1_AD_DECRYPT_ERROR);
    case SSL_AD_EXPORT_RESTRICTION:
        return (TLS1_AD_EXPORT_RESTRICTION);
    case SSL_AD_PROTOCOL_VERSION:
        return (TLS1_AD_PROTOCOL_VERSION);
    case SSL_AD_INSUFFICIENT_SECURITY:
        return (TLS1_AD_INSUFFICIENT_SECURITY);
    case SSL_AD_INTERNAL_ERROR:
        return (TLS1_AD_INTERNAL_ERROR);
    case SSL_AD_USER_CANCELLED:
        return (TLS1_AD_USER_CANCELLED);
    case SSL_AD_NO_RENEGOTIATION:
        return (TLS1_AD_NO_RENEGOTIATION);
    case SSL_AD_UNSUPPORTED_EXTENSION:
        return (TLS1_AD_UNSUPPORTED_EXTENSION);
    case SSL_AD_CERTIFICATE_UNOBTAINABLE:
        return (TLS1_AD_CERTIFICATE_UNOBTAINABLE);
    case SSL_AD_UNRECOGNIZED_NAME:
        return (TLS1_AD_UNRECOGNIZED_NAME);
    case SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        return (TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE);
    case SSL_AD_BAD_CERTIFICATE_HASH_VALUE:
        return (TLS1_AD_BAD_CERTIFICATE_HASH_VALUE);
    case SSL_AD_UNKNOWN_PSK_IDENTITY:
        return (TLS1_AD_UNKNOWN_PSK_IDENTITY);
    case SSL_AD_INAPPROPRIATE_FALLBACK:
        return (TLS1_AD_INAPPROPRIATE_FALLBACK);
#if 0
        /* not appropriate for TLS, not used for DTLS */
    case DTLS1_AD_MISSING_HANDSHAKE_MESSAGE:
        return (DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);
#endif
    default:
        return (-1);
    }
}
