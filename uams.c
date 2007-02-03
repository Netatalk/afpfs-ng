/*
 *  uams.c
 *
 *  Copyright (C) 2006 Alex deVries
 *  Copyright (C) 2007 Derrik Pates
 *
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "log.h"
#include "uams_def.h"
#include "config.h"

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */
#ifdef HAVE_LIBGMP
#include <gmp.h>
#endif /* HAVE_LIBGMP */

struct afp_uam {
	unsigned int bitmap;
	char name[AFP_UAM_LENGTH];
	int (*do_server_login)(struct afp_server *server, char *username, char *password);
	struct afp_uam * next;
};

static struct afp_uam * uam_base = NULL;

static int noauth_login(struct afp_server *server, char *username, char *passwd);
static int cleartxt_login(struct afp_server *server, char *username, char *passwd);
#ifdef HAVE_LIBGCRYPT
static int randnum_login(struct afp_server *server, char *username,
		char *passwd);
static int randnum2_login(struct afp_server *server, char *username,
		char *passwd);
#ifdef HAVE_LIBGMP
static int dhx_login(struct afp_server *server, char *username, char *passwd);
static int dhx2_login(struct afp_server *server, char *username, char *passwd);
#endif /* HAVE_LIBGMP */
#endif /* HAVE_LIBGCRYPT */

static struct afp_uam uam_noauth = 
	{UAM_NOUSERAUTHENT,"No User Authent",&noauth_login,NULL};
static struct afp_uam uam_cleartxt = 
	{UAM_CLEARTXTPASSWRD,"Cleartxt Passwrd",&cleartxt_login,NULL};
#ifdef HAVE_LIBGCRYPT
static struct afp_uam uam_randnum = 
	{UAM_RANDNUMEXCHANGE, "Randnum Exchange", &randnum_login, NULL};
static struct afp_uam uam_randnum2 = 
	{UAM_2WAYRANDNUM, "2-Way Randnum Exchange", &randnum2_login, NULL};
#ifdef HAVE_LIBGMP
static struct afp_uam uam_dhx = 
	{UAM_DHCAST128, "DHCAST128", &dhx_login, NULL};
static struct afp_uam uam_dhx2 = 
	{UAM_DHX2, "DHX2", &dhx2_login, NULL};
#endif /* HAVE_LIBGMP */
#endif /* HAVE_LIBGCRYPT */


static int register_uam(struct afp_uam * uam) 
{

	struct afp_uam * u = uam_base;
	if ((uam->bitmap=uam_string_to_bitmap(uam->name))==0) goto error;
	if (!uam_base)  {
		uam_base=uam;
		u=uam;
	} else {
		for (;u->next;u=u->next);
		u->next=uam;
	}
	uam->next=NULL;
	return 0;
error:
	LOG(AFPFSD,LOG_WARNING,
		"Could not register all UAMs\n");
	return -1;
}

static struct afp_uam * find_uam_by_bitmap(unsigned int i)
{
	struct afp_uam * u=uam_base;
	for (;u;u=u->next)
		if (u->bitmap==i)
			return u;
	return NULL;
}


int init_uams(void) {
	register_uam(&uam_cleartxt);
	register_uam(&uam_noauth);
#ifdef HAVE_LIBGCRYPT
	register_uam(&uam_randnum);
	register_uam(&uam_randnum2);
#ifdef HAVE_LIBGMP
	register_uam(&uam_dhx);
	register_uam(&uam_dhx2);
#endif /* HAVE_LIBGMP */
#endif /* HAVE_LIBGCRYPT */
	return 0;
}

static int noauth_login(struct afp_server *server, char *username, char *passwd) {
	return afp_login(server, "No User Authent", NULL, 0, NULL);
}

static int cleartxt_login(struct afp_server *server, char *username, char *passwd) {
	char *p, *ai = NULL;
	int passwdlen = strlen(passwd);
	int len = strlen(username) + 10;
	int ret;

	ai = malloc(len);
	if (ai == NULL) 
		return -1;
	memset(ai, 0, len);

	p = ai;
	p += copy_to_pascal(p, username) + 1;
	if ((int)p & 0x1)
		len--;
	else
		p++;

	if (passwdlen > 8)
		passwdlen=8;
	memcpy(p, passwd, passwdlen);

	ret = afp_login(server, "Cleartxt Passwrd", ai, len, NULL);
	free(ai);

	return ret;
}

#ifdef HAVE_LIBGCRYPT

static int randnum_login(struct afp_server *server, char *username,
		char *passwd) {
	char *ai = NULL;
	char key_buffer[8], crypted[8];
	int ai_len = strlen(username) + 1;
	int ret;
	gcry_cipher_hd_t ctx;
	gcry_error_t ctxerror;
	struct afp_rx_buffer rbuf;
	unsigned short ID;
	unsigned char randnum[8];

	rbuf.maxsize = 10;
	rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto randnum_noctx_fail;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	ai = malloc(ai_len);
	if (ai == NULL)
		goto randnum_noctx_fail;
	memset(ai, 0, ai_len);
	copy_to_pascal(ai, username);

	/* Send the initial FPLogin request to the server. */
	ret = afp_login(server, "Randnum Exchange", ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto randnum_noctx_cleanup;

	/* For now, if the response block from the server isn't *exactly*
	 * 10 bytes long (if we got kFPAuthContinue with this UAM, it
	 * should never be any other size), die a horrible death.
	 */
	if (rbuf.size != 10)
		assert("size of data returned during randnum auth process was wrong size, should be 10 bytes!");

	/* Copy the relevant values out of the response block the server
	 * sent to us.
	 */
	memcpy(&ID, rbuf.data, sizeof(ID));
	ID = ntohs(ID);
	memcpy(randnum, rbuf.data + sizeof(ID), sizeof(randnum));
	free(rbuf.data);
	rbuf.data = NULL;

	/* Establish encryption context for doing password encryption work. */
	ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_ECB, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum_noctx_fail;

	/* Copy (up to 8 characters of) the password into key_buffer, after
	 * zeroing it out first.
	 */
	strncpy(key_buffer, passwd, sizeof(key_buffer));

	/* Set the provided password (now in key_buffer) as the encryption
	 * key in our established context, for subsequent use to encrypt
	 * the random number that the server sends us.
	 */
	ctxerror = gcry_cipher_setkey(ctx, key_buffer, sizeof(key_buffer));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum_fail;

	/* Encrypt the random number data into crypted[]. */
	ctxerror = gcry_cipher_encrypt(ctx, crypted, sizeof(crypted),
			randnum, sizeof(randnum));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum_fail;

	/* Send the FPLoginCont to the server, containing the server's
	 * random number encrypted with the password.
	 */
	ret = afp_logincont(server, ID, crypted, sizeof(crypted), NULL);

	goto randnum_cleanup;

randnum_noctx_fail:
	ret = -1;
	goto randnum_noctx_cleanup;
randnum_fail:
	ret = -1;
randnum_cleanup:
	/* Destroy the encryption context. */
	gcry_cipher_close(ctx);
randnum_noctx_cleanup:
	free(rbuf.data);
	free(ai);
	return ret;
}

static int randnum2_login(struct afp_server *server, char *username, char *passwd) {
	char *ai = NULL;
	char *p = NULL;
	char key_buffer[8], crypted[8];
	int ai_len = strlen(username) + 1;
	int ret;
	int i, carry, carry2;
	gcry_cipher_hd_t ctx;
	gcry_error_t ctxerror;
	struct afp_rx_buffer rbuf;
	unsigned short ID;
	char randnum[8], my_randnum[8];
	FILE *rand_fh = NULL;

	rbuf.maxsize = 10;
	rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		return -1;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	ai = malloc(ai_len);
	if (ai == NULL)
		goto randnum2_noctx_fail;
	memset(ai, 0, ai_len);
	copy_to_pascal(ai, username);

	/* Send the initial FPLogin request to the server. */
	ret = afp_login(server, "2-Way Randnum Exchange", ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto randnum2_noctx_cleanup;

	/* For now, if the response block from the server isn't *exactly*
	 * 10 bytes long (if we got kFPAuthContinue with this UAM, it
	 * should never be any other size), die a horrible death.
	 */
	if (rbuf.size != 10)
		assert("size of data returned during randnum2 auth process was wrong size, should be 10 bytes!");

	/* Copy the relevant values out of the response block the server
	 * sent to us.
	 */
	memcpy(&ID, rbuf.data, sizeof(ID));
	ID = ntohs(ID);
	memcpy(randnum, rbuf.data + sizeof(ID), sizeof(randnum));
	free(rbuf.data);
	rbuf.data = NULL;

	/* Establish encryption context for doing password encryption work. */
	ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_ECB, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum2_noctx_fail;

	/* Copy (up to 8 characters of) the password into key_buffer, after
	 * zeroing it out first.
	 */
	strncpy(key_buffer, passwd, sizeof(key_buffer));

	/* Rotate each byte left one bit, carrying the high bit to the next. */
	carry = 0;
	for (i = sizeof(key_buffer) - 1; i >= 0; i--) {
		carry2 = key_buffer[i] >> 7;
		key_buffer[i] = key_buffer[i] << 1 | carry;
		carry = carry2;
	}
	/* Once we've reached the first byte, use its carried value to OR
	 * into the last byte, so the shift is complete.
	 */
	key_buffer[sizeof(key_buffer) - 1] |= carry;

	/* Set the provided password (now in key_buffer) as the encryption
	 * key in our established context, for subsequent use to encrypt
	 * the random number that the server sends us.
	 */
	ctxerror = gcry_cipher_setkey(ctx, key_buffer, 8);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum2_fail;

	/* Encrypt the random number data into crypted[]. */
	ctxerror = gcry_cipher_encrypt(ctx, crypted, 8, randnum, 8);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum2_fail;

	/* Setup a new authinfo block for the FPLoginCont invocation. It will
	 * contain the DES hashed password, followed by our chosen random
	 * number, which the server will use to hash the password and then
	 * send back to us for comparison.
	 */
	ai = malloc(ai_len = sizeof(crypted) + sizeof(my_randnum));
	if (ai == NULL)
		goto randnum2_fail;
	memset(ai, 0, ai_len);
	strncpy(ai, crypted, sizeof(crypted));
	p = ai + sizeof(crypted);

	/* Open up /dev/urandom and get a new random number, just for us. */
	rand_fh = fopen("/dev/urandom", "r");
	if (rand_fh == NULL)
		goto randnum2_fail;
	if (fread(my_randnum, 1, sizeof(my_randnum), rand_fh)
			!= sizeof(my_randnum))
		goto randnum2_fail;

	fclose(rand_fh);
	rand_fh = NULL;
	/* Copy our random number into the authinfo block, so the server
	 * can use it to encrypt its copy of the password, which it should
	 * have (this prevents us from connecting to a bogus server that's
	 * stealing passwords, or at least lets us know it's happening...)
	 */
	memcpy(p, my_randnum, sizeof(my_randnum));

	rbuf.maxsize = 8;
	rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto randnum2_fail;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	/* Send the FPLoginCont to the server, containing the server's
	 * random number encrypted with the password, and our random number.
	 */
	ret = afp_logincont(server, ID, ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;

	if (ret != kFPNoErr)
		goto randnum2_cleanup;

	if (rbuf.size != 8)
		assert("size of data returned during randnum2 auth process was wrong size, should be 8 bytes!");

	/* Encrypt our random number data into crypted[]. */
	ctxerror = gcry_cipher_encrypt(ctx, crypted, 8, my_randnum, 8);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum2_fail;

	/* If they didn't match, tell the caller that the user wasn't
	 * authenticated, so it'll junk the connection.
	 */
	if (memcmp(crypted, rbuf.data, sizeof(crypted)) != 0)
		ret = kFPUserNotAuth;

	goto randnum2_cleanup;

randnum2_noctx_fail:
	ret = -1;
	goto randnum2_noctx_cleanup;
randnum2_fail:
	ret = -1;
randnum2_cleanup:
	/* Destroy the encryption context. */
	gcry_cipher_close(ctx);
randnum2_noctx_cleanup:
	if (rand_fh != NULL)
		fclose(rand_fh);
	free(rbuf.data);
	free(ai);
	return ret;
}

#ifdef HAVE_LIBGMP

/* The initialization vectors are universally fixed. These are the values
 * documented by Apple.
 */
static unsigned char dhx_c2siv[] = { 'L', 'W', 'a', 'l', 'l', 'a', 'c', 'e' };
static unsigned char dhx_s2civ[] = { 'C', 'J', 'a', 'l', 'b', 'e', 'r', 't' };

/* The values of p and g are fixed for DHCAST128. */
static unsigned char p_binary[] = { 0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57,
		0xd4, 0x3f, 0x20, 0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b };
static unsigned char g_binary[] = { 0x07 };

static int dhx_login(struct afp_server *server, char *username, char *passwd) {
	char *ai = NULL, *d = NULL, *plaintext = NULL;
	unsigned char Ra_binary[32], K_binary[16];
	int ai_len, ret;
	const int Ma_len = 16, Mb_len = 16, nonce_len = 16;
	mpz_t p, g, Ra, Ma, Mb, K, nonce, new_nonce;
	size_t len;
	FILE *rand_fh = NULL;
	struct afp_rx_buffer rbuf;
	unsigned short ID;
	gcry_cipher_hd_t ctx;
	gcry_error_t ctxerror;

	rbuf.data = NULL;
	/* Initialize all mpz_t variables, so they can all be uninitialized
	 * in an orderly manner later.
	 */
	mpz_init(p);
	mpz_init(g);
	mpz_init(Ra);
	mpz_init(Ma);
	mpz_init(Mb);
	mpz_init(K);
	mpz_init(nonce);
	mpz_init(new_nonce);

	/* Get p and g into a form that GMP can use */
	mpz_import(p, sizeof(p_binary), 1, 1, 1, 0, p_binary);
	mpz_import(g, sizeof(g_binary), 1, 1, 1, 0, g_binary);

	/* Open /dev/urandom to read some fairly random bytes to be used as
	 * our Ra value in the Diffie-Hellman exchange.
	 */
	rand_fh = fopen("/dev/urandom", "r");
	if (rand_fh == NULL)
		goto dhx_noctx_fail;
	len = fread(Ra_binary, 1, sizeof(Ra_binary), rand_fh);
	if (len != 32)
		goto dhx_noctx_fail;

	fclose(rand_fh);
	rand_fh = NULL;

	/* Translate the binary form of Ra into GMP's preferred form */
	mpz_import(Ra, sizeof(Ra_binary), 1, 1, 1, 0, Ra_binary);

	/* Ma = g^Ra mod p <- This is our "public" key, which we exchange
	 * with the remote server to help make K, the session key.
	 */
	mpz_powm(Ma, g, Ra, p);

	/* The first authinfo block, containing the username and our Ma
	 * value */
	ai_len = 1 + strlen(username) + 1 + Ma_len;
	d = ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx_noctx_fail;
	memset(ai, 0, ai_len);
	copy_to_pascal(ai, username);
	d += 1 + strlen(username);
	if (((int)d) % 2)
		d++;
	else
		ai_len--;
	
	mpz_export(d, &len, 1, 1, 1, 0, Ma);
	if (len < Ma_len) {
		memmove(d + Ma_len - len, d, len);
		memset(d, 0, Ma_len - len);
	}

	/* 2 bytes for id, 16 bytes for Mb, 32 bytes of crypted message text */
	rbuf.maxsize = 2 + Mb_len + 32;
	rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto dhx_noctx_fail;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	/* Send the first FPLogin request, and see what happens. */
	ret = afp_login(server, "DHCAST128", ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto dhx_noctx_cleanup;

	/* The block returned from the server should always be 50 bytes.
	 * If it's not, for now, choke and die loudly so we know it.
	 */
	if (rbuf.size != 50)
		assert("size of data returned during dhx auth process was wrong size, should be 50 bytes!");

	d = rbuf.data;
	/* Extract the transaction ID from the server's reply block. */
	memcpy(&ID, d, sizeof(ID));
	d += sizeof(ID);
	ID = ntohs(ID);
	/* Now, extract Mb (the server's "public key" part) directly into
	 * an mpz_t for use with GMP.
	 */
	mpz_import(Mb, Mb_len, 1, 1, 1, 0, d);
	d += Mb_len;
	/* d now points to the ciphertext, which we'll decrypt in a bit. */

	/* K = Mb^Ra mod p <- This nets us the "session key", which we
	 * actually use to encrypt and decrypt data.
	 */
	mpz_powm(K, Mb, Ra, p);
	mpz_export(K_binary, &len, 1, 1, 1, 0, K);
	if (len < sizeof(K_binary)) {
		memmove(K_binary + (sizeof(K_binary) - len), K_binary, len);
		memset(K_binary, 0, sizeof(K_binary) - len);
	}
	/* FIXME: To support the Reconnect UAM, we need to stash this key
	 * somewhere in the session data. We'll worry about doing that
	 * later, but this would be a prime spot to do that.
	 */

	/* Set up our encryption context. */
	ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
			GCRY_CIPHER_MODE_CBC, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_noctx_fail;

	/* Set the binary form of K as our key for this encryption context. */
	ctxerror = gcry_cipher_setkey(ctx, K_binary, sizeof(K_binary));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;

	/* Set the initialization vector for server->client transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;

	/* The plaintext will hold the nonce (16 bytes) and the server's
	 * signature (16 bytes - we don't actually look at it though).
	 */
	len = nonce_len + 16;
	plaintext = malloc(len);
	if (plaintext == NULL)
		goto dhx_fail;
	memset(plaintext, 0, len);
	
	/* Decrypt the ciphertext from the server. */
	ctxerror = gcry_cipher_decrypt(ctx, plaintext, len, d, len);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;
	/* d still points into rbuf.data, which is no longer needed. */
	free(rbuf.data);
	rbuf.data = NULL;

	/* Pull the binary form of the nonce into a form that GMP can
	 * deal with.
	 */
	mpz_import(nonce, nonce_len, 1, 1, 1, 0, plaintext);
	/* Copy the server signature out of the plaintext. NOTE: This will
	 * always contain just 0 values - Apple's docs claim that due to
	 * an error in an early implementation, it will always be that
	 * way - I just ignore it. This could really go away since it's
	 * nonfunctional anyway...
	 */
	/* memcpy(serverSig, plaintext + 16, sizeof(serverSig)); */
	free(plaintext);
	plaintext = NULL;

	/* Increment the nonce by 1 for sending back to the server. */
	mpz_add_ui(new_nonce, nonce, 1);
	
	/* New plaintext is 16 bytes of nonce, and (up to) 64 bytes of
	 * password (filled out with NULL values).
	 */
	ai_len = nonce_len + 64;
	plaintext = malloc(ai_len);
	if (plaintext == NULL)
		goto dhx_fail;
	memset(plaintext, 0, ai_len);

	/* Pull the incremented nonce value back out into binary form. */
	mpz_export(plaintext, &len, 1, 1, 1, 0, new_nonce);
	if (len < 16) {
		memmove(plaintext + nonce_len - len, plaintext, len);
		memset(plaintext, 0, nonce_len - len);
	}
	/* Copy the user's password into the plaintext. */
	strncpy(plaintext + nonce_len, passwd, 64);

	/* Set the initialization vector for client->server transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;

	ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx_fail;
	memset(ai, 0, ai_len);

	/* Encrypt the plaintext to create our new authinfo block. */
	ctxerror = gcry_cipher_encrypt(ctx, ai, ai_len, plaintext, ai_len);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;
	free(plaintext);
	plaintext = NULL;

	/* Send the FPLoginCont with the new authinfo block, sit back,
	 * cross fingers...
	 */
	ret = afp_logincont(server, ID, ai, ai_len, NULL);

	goto dhx_cleanup;
dhx_noctx_fail:
	ret = -1;
	goto dhx_noctx_cleanup;
dhx_fail:
	ret = -1;
dhx_cleanup:
	gcry_cipher_close(ctx);
dhx_noctx_cleanup:
	if (rand_fh != NULL)
		fclose(rand_fh);
	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(Ra);
	mpz_clear(Ma);
	mpz_clear(Mb);
	mpz_clear(K);
	mpz_clear(nonce);
	mpz_clear(new_nonce);
	free(ai);
	free(plaintext);
	free(rbuf.data);
	return ret;
}

static int dhx2_login(struct afp_server *server, char *username, char *passwd) {
	mpz_t p, g, Ma, Mb, Ra, K, nonce, new_nonce;
	char *ai = NULL, *d, *Ra_binary = NULL, *K_binary = NULL;
	char K_hash[16], nonce_binary[16], *plaintext = NULL;
	int ai_len, ret;
	size_t len;
	struct afp_rx_buffer rbuf;
	unsigned short ID, bignum_len;
	FILE *rand_fh = NULL;
	gcry_cipher_hd_t ctx;
	gcry_error_t ctxerror;

	rbuf.data = NULL;
	mpz_init(p);
	mpz_init(g);
	mpz_init(Ra);
	mpz_init(Ma);
	mpz_init(Mb);
	mpz_init(K);
	mpz_init(nonce);
	mpz_init(new_nonce);

	ai_len = strlen(username) + 2;
	d = ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx2_noctx_fail;
	memset(ai, 0, ai_len);
	copy_to_pascal(ai, username);
	d += 1 + strlen(username);
	if (((int)d) % 2)
		ai_len--;

	/* Reply block will contain:
	 *   Transaction ID (2 bytes, MSB)
	 *   g (4 bytes, MSB)
	 *   length of large values in bytes (2 bytes, MSB)
	 *   p (minimum 64 bytes, indicated by length value, MSB)
	 *   Mb (minimum 64 bytes, indicated by length value, MSB)
	 * We'll reserve 256 bytes for each.
	 * FIXME: We need to retool this to handle any length for p and Mb;
	 * I've only ever seen it be 64 bytes, but it could easily be larger.
	 */
	rbuf.maxsize = 2 + 4 + 2 + 256 + 256;
	d = rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto dhx2_noctx_fail;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	ret = afp_login(server, "DHX2", ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto dhx2_noctx_cleanup;

	/* Pull the transaction ID out of the reply block. */
	memcpy(&ID, d, sizeof(ID));
	ID = ntohs(ID);
	d += sizeof(ID);

	/* Pull the value of g out of the reply block and directly into an
	 * mpz_t container for later use with GMP.
	 */
	mpz_import(g, 4, 1, 1, 1, 0, d);
	d += 4;

	memcpy(&bignum_len, d, sizeof(bignum_len));
	bignum_len = ntohs(bignum_len);
	d += sizeof(bignum_len);

	if (bignum_len > 256)
		assert("server indicates large number length too large for us (> 256 bytes)?");

	/* Extract p into an mpz_t. */
	mpz_import(p, bignum_len, 1, 1, 1, 0, d);
	d += bignum_len;

	/* Extract Mb into an mpz_t. */
	mpz_import(Mb, bignum_len, 1, 1, 1, 0, d);

	free(rbuf.data);
	rbuf.data = NULL;
	
	Ra_binary = malloc(bignum_len);
	if (Ra_binary == NULL)
		goto dhx2_noctx_fail;
	memset(Ra_binary, 0, bignum_len);
	/* Open /dev/urandom to read some fairly random bytes to be used as
	 * our Ra value in the Diffie-Hellman exchange.
	 */
	rand_fh = fopen("/dev/urandom", "r");
	if (rand_fh == NULL)
		goto dhx2_noctx_fail;
	len = fread(Ra_binary, 1, bignum_len, rand_fh);
	if (len != bignum_len)
		goto dhx2_noctx_fail;

	/* Pull the random value we just read into an mpz_t so we can do
	 * large-value exponentiation, and generate our Ma.
	 */
	mpz_import(Ra, bignum_len, 1, 1, 1, 0, Ra_binary);
	free(Ra_binary);
	Ra_binary = NULL;

	/* Ma = g^Ra mod p <- This is our "public" key, which we exchange
	 * with the remote server to help make K, the session key.
	 */
	mpz_powm(Ma, g, Ra, p);

	/* K = Mb^Ra mod p <- This nets us the "session key", which we
	 * actually use to encrypt and decrypt data.
	 */
	mpz_powm(K, Mb, Ra, p);
	K_binary = malloc(bignum_len);
	if (K_binary == NULL)
		goto dhx2_noctx_fail;
	memset(K_binary, 0, bignum_len);
	mpz_export(K_binary, &len, 1, 1, 1, 0, K);
	if (len < bignum_len) {
		memmove(K_binary + bignum_len - len, K_binary, len);
		memset(K_binary, 0, bignum_len - len);
	}

	/* Use a one-shot hash function to generate the MD5 hash of K. */
	gcry_md_hash_buffer(GCRY_MD_MD5, K_hash, K_binary, bignum_len);
	/* FIXME: To support the Reconnect UAM, we need to stash this key
	 * somewhere in the session data. We'll worry about doing that
	 * later, but this would be a prime spot to do that.
	 */

	/* Generate our nonce to send to the server. */
	len = fread(nonce_binary, 1, sizeof(nonce_binary), rand_fh);
	if (len != sizeof(nonce_binary))
		goto dhx2_noctx_fail;

	/* Set up our encryption context. */
	ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
			GCRY_CIPHER_MODE_CBC, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_noctx_fail;

	/* Set the binary form of K as our key for this encryption context. */
	ctxerror = gcry_cipher_setkey(ctx, K_hash, sizeof(K_hash));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	/* Set the initialization vector for client->server transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_s2civ));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	/* The new authinfo block will contain Ma (our "public" key part) and
	 * the encrypted form of our nonce.
	 */
	ai_len = bignum_len + sizeof(nonce_binary);
	d = ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx2_fail;
	mpz_export(d, &len, 1, 1, 1, 0, Ma);
	if (len < bignum_len) {
		memmove(d + bignum_len - len, d, len);
		memset(d, 0, bignum_len - len);
	}
	d += bignum_len;

	/* Encrypt our nonce into the new authinfo block. */
	ctxerror = gcry_cipher_encrypt(ctx, d, sizeof(nonce_binary),
			nonce_binary, sizeof(nonce_binary));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	/* Reply block will contain ID, then the encrypted form of our
	 * nonce + 1 and the server's nonce.
	 */
	rbuf.maxsize = 2 + sizeof(nonce_binary) * 2;
	d = rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto dhx2_fail;
	memset(rbuf.data, 0, rbuf.maxsize);
	rbuf.size = 0;

	ret = afp_logincont(server, ID, ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto dhx2_cleanup;

	/* Get the new transaction ID for the last portion of the exchange. */
	memcpy(&ID, d, sizeof(ID));
	ID = ntohs(ID);
	d += sizeof(ID);

	len = sizeof(nonce_binary) * 2;
	plaintext = malloc(len);
	if (plaintext == NULL)
		goto dhx2_fail;
	memset(plaintext, 0, len);

	/* Set the initialization vector for server->client transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	/* Decrypt the ciphertext from the server. */
	ctxerror = gcry_cipher_decrypt(ctx, plaintext, len, d, len);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;
	
	free(rbuf.data);
	rbuf.data = NULL;

	/* Pull our nonce into an mpz_t so we can operate. */
	mpz_import(nonce, sizeof(nonce_binary), 1, 1, 1, 0, nonce_binary);
	/* Increment our nonce by one. */
	mpz_add_ui(new_nonce, nonce, 1);
	/* Pull the incremented nonce back out into binary form. */
	mpz_export(nonce_binary, &len, 1, 1, 1, 0, new_nonce);
	if (len < sizeof(nonce_binary)) {
		memmove(nonce_binary + sizeof(nonce_binary) - len,
				nonce_binary, len);
		memset(nonce_binary, 0, sizeof(nonce_binary) - len);
	}

	/* Compare our incremented nonce to the server's incremented copy
	 * of our original nonce value; if they don't match, something
	 * terrible has happened.
	 */
	if (memcmp(nonce_binary, plaintext, 16) != 0)
		assert("nonce check failed while running dhx2 authentication");

	d = plaintext + sizeof(nonce_binary);

	/* Pull the server's nonce value into an mpz_t. */
	mpz_import(nonce, sizeof(nonce_binary), 1, 1, 1, 0, d);
	free(plaintext);
	plaintext = NULL;
	/* Increment the server's nonce by one. */
	mpz_add_ui(new_nonce, nonce, 1);
	
	/* The new plaintext will need 16 bytes for the server nonce (after
	 * incrementing), followed by 256 bytes of null-filled space for the
	 * user's password. */
	len = sizeof(nonce_binary) + 256;
	d = plaintext = malloc(len);
	if (plaintext == NULL)
		goto dhx2_fail;
	memset(plaintext, 0, len);

	/* Extract the binary form of the incremented server nonce into
	 * the plaintext buffer. */
	mpz_export(plaintext, &len, 1, 1, 1, 0, new_nonce);
	if (len < sizeof(nonce_binary)) {
		memmove(plaintext + sizeof(nonce_binary) - len,
				plaintext, len);
		memset(plaintext, 0, sizeof(nonce_binary) - len);
	}
	d += sizeof(nonce_binary);
	/* Copy the user's password into the plaintext buffer. */
	strncpy(d, passwd, 256);

	/* Final authinfo block contains the full length of the encrypted
	 * plaintext - 16 bytes of nonce data, and 256 bytes of null-filled
	 * space for the user's password. */
	ai_len = sizeof(nonce_binary) + 256;
	ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx2_fail;
	memset(ai, 0, ai_len);

	/* Set the initialization vector for client->server transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_s2civ));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	/* Encrypt our nonce into the new authinfo block. */
	ctxerror = gcry_cipher_encrypt(ctx, ai, ai_len, plaintext, ai_len);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx2_fail;

	free(plaintext);
	plaintext = NULL;

	/* Send the FPLoginCont with the new authinfo block, sit back,
	 * cross fingers...
	 */
	ret = afp_logincont(server, ID, ai, ai_len, NULL);

	goto dhx2_cleanup;

dhx2_noctx_fail:
	ret = -1;
	goto dhx2_noctx_cleanup;
dhx2_fail:
	ret = -1;
dhx2_cleanup:
	gcry_cipher_close(ctx);
dhx2_noctx_cleanup:
	if (rand_fh != NULL)
		fclose(rand_fh);
	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(Ra);
	mpz_clear(Ma);
	mpz_clear(Mb);
	mpz_clear(K);
	mpz_clear(nonce);
	mpz_clear(new_nonce);
	free(plaintext);
	free(Ra_binary);
	free(K_binary);
	free(ai);
	free(rbuf.data);
	return ret;
}

#endif /* HAVE_LIBGMP */
#endif /* HAVE_LIBGCRYPT */

int afp_dologin(struct afp_server *server, 
		unsigned int uam, char * username, char * passwd)
{

	struct afp_uam * u;
	char * uam_name = uam_bitmap_to_string(uam);

	if (!uam_name) {
		LOG(AFPFSD,LOG_WARNING,
			"Unknown uam string\n");
		return -1;
	}

	if ((u=find_uam_by_bitmap(uam))==NULL) {
		LOG(AFPFSD,LOG_WARNING,
			"Unknown uam\n");
		return -1;
	}

	return u->do_server_login(server, username, passwd);
}

