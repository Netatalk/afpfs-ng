/*
 *  uams.c
 *
 *  Copyright (C) 2006 Alex deVries
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

#ifdef HAS_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAS_LIBGCRYPT */
#ifdef HAS_LIBGMP
#include <gmp.h>
#endif /* HAS_LIBGMP */

struct afp_uam {
	unsigned int bitmap;
	char name[AFP_UAM_LENGTH];
	int (*do_server_login)(struct afp_server *server, char *username, char *password);
	struct afp_uam * next;
};

static struct afp_uam * uam_base = NULL;

static int noauth_login(struct afp_server *server, char *username, char *passwd);
static int cleartxt_login(struct afp_server *server, char *username, char *passwd);
#ifdef HAS_LIBGCRYPT
static int randnum_login(struct afp_server *server, char *username,
		char *passwd);
static int randnum2_login(struct afp_server *server, char *username,
		char *passwd);
#ifdef HAS_LIBGMP
static int dhx_login(struct afp_server *server, char *username, char *passwd);
#if 0
static int dhx2_login(struct afp_server *server, char *username, char *passwd);
#endif
#endif /* HAS_LIBGMP */
#endif /* HAS_LIBGCRYPT */

static struct afp_uam uam_noauth = 
	{UAM_NOUSERAUTHENT,"No User Authent",&noauth_login,NULL};
static struct afp_uam uam_cleartxt = 
	{UAM_CLEARTXTPASSWRD,"Cleartxt Passwrd",&cleartxt_login,NULL};
#ifdef HAS_LIBGCRYPT
static struct afp_uam uam_randnum = 
	{UAM_RANDNUMEXCHANGE, "Randnum Exchange", &randnum_login, NULL};
static struct afp_uam uam_randnum2 = 
	{UAM_2WAYRANDNUM, "2-Way Randnum", &randnum2_login, NULL};
#ifdef HAS_LIBGMP
static struct afp_uam uam_dhx = 
	{UAM_DHCAST128, "DHCAST128", &dhx_login, NULL};
#if 0
static struct afp_uam uam_dhx2 = 
	{UAM_DHX2, "DHX2", &dhx2_login, NULL};
#endif
#endif /* HAS_LIBGMP */
#endif /* HAS_LIBGCRYPT */


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
#ifdef HAS_LIBGCRYPT
	register_uam(&uam_randnum);
	register_uam(&uam_randnum2);
#ifdef HAS_LIBGMP
	register_uam(&uam_dhx);
#if 0
	register_uam(&uam_dhx2);
#endif
#endif /* HAS_LIBGMP */
#endif /* HAS_LIBGCRYPT */
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

#ifdef HAS_LIBGCRYPT

static int randnum_login(struct afp_server *server, char *username,
		char *passwd) {
	char *ai = NULL;
	char key_buffer[8], crypted[8];
	int ai_len = strlen(username) + 1;
	int key_len;
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

	/* Establish encryption context for doing password encryption work. */
	ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_NONE, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum_noctx_fail;

	/* Copy (up to 8 characters of) the password into key_buffer, after
	 * zeroing it out first.
	 */
	memset(key_buffer, 0, sizeof(key_buffer));
	key_len = strlen(passwd);
	if (key_len > sizeof(key_buffer))
		key_len = sizeof(key_buffer);
	strncpy(key_buffer, passwd, key_len);

	/* Set the provided password (now in key_buffer) as the encryption
	 * key in our established context, for subsequent use to encrypt
	 * the random number that the server sends us.
	 */
	ctxerror = gcry_cipher_setkey(ctx, key_buffer, sizeof(key_buffer));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum_fail;

	/* Encrypt the random number data into crypted[]. */
	ctxerror = gcry_cipher_encrypt(ctx, crypted, 8, randnum, 8);
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
	int key_len;
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
	ret = afp_login(server, "2-Way Randnum", ai, ai_len, &rbuf);
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
			GCRY_CIPHER_MODE_NONE, 0);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto randnum2_noctx_fail;

	/* Copy (up to 8 characters of) the password into key_buffer, after
	 * zeroing it out first.
	 */
	memset(key_buffer, 0, sizeof(key_buffer));
	key_len = strlen(passwd);
	if (key_len > sizeof(key_buffer))
		key_len = sizeof(key_buffer);
	strncpy(key_buffer, passwd, key_len);

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

#ifdef HAS_LIBGMP

static unsigned char dhx_c2siv[] = { 'L', 'W', 'a', 'l', 'l', 'a', 'c', 'e' };
static unsigned char dhx_s2civ[] = { 'C', 'J', 'a', 'l', 'b', 'e', 'r', 't' };

static unsigned char dhx_p[] = { 0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57,
		0xd4, 0x3f, 0x20, 0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b };
static unsigned char dhx_g[] = { 0x07 };

static int dhx_login(struct afp_server *server, char *username, char *passwd) {
	char *ai = NULL, *d = NULL, *plaintext = NULL;
	int ai_len, ret;
	mpz_t p, g, Ra, Ma, Mb, K, nonce, new_nonce;
	unsigned char Ra_binary[32], Ma_binary[16], Mb_binary[16];
	unsigned char K_binary[16], nonce_binary[16], serverSig[16];
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
	mpz_import(p, sizeof(dhx_p), 1, 1, 1, 0, dhx_p);
	mpz_import(g, sizeof(dhx_g), 1, 1, 1, 0, dhx_g);

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
	mpz_export(Ma_binary, &len, 1, 1, 1, 0, Ma);
	if (len < sizeof(Ma_binary)) {
		memmove(Ma_binary + (sizeof(Ma_binary) - len), Ma_binary, len);
		memset(Ma_binary, 0, sizeof(Ma_binary) - len);
	}

	/* The first authinfo block, containing the username and our Ma
	 * value */
	ai_len = 1 + strlen(username) + 1 + sizeof(Ma_binary);
	ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx_noctx_fail;
	memset(ai, 0, ai_len);
	copy_to_pascal(ai, username);
	d = ai + 1 + strlen(username);
	if (((int)d) % 2)
		d++;
	else
		ai_len--;
	
	memcpy(d, Ma_binary, sizeof(Ma_binary));

	/* 2 bytes for id, 16 bytes for Mb, 32 bytes of crypted message text */
	rbuf.maxsize = 50;
	rbuf.data = malloc(rbuf.maxsize);
	if (rbuf.data == NULL)
		goto dhx_noctx_fail;
		
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
	/* Now, extract Mb (the server's "public key" part) */
	memcpy(Mb_binary, d, sizeof(Mb_binary));
	d += sizeof(Mb_binary);
	/* d now points to the ciphertext, which we'll decrypt in a bit. */

	/* Pull the binary form of Mb into the right form for GMP, so we
	 * can do some math with it.
	 */
	mpz_import(Mb, sizeof(Mb_binary), 1, 1, 1, 0, Mb_binary);

	/* K = Mb^Ra mod p <- This nets us the "session key", which we
	 * actually use to encrypt and decrypt data.
	 */
	mpz_powm(K, Mb, Ra, p);
	mpz_export(K_binary, &len, 1, 1, 1, 0, K);
	if (len < sizeof(K_binary)) {
		memmove(K_binary + (sizeof(K_binary) - len), K_binary, len);
		memset(K_binary, 0, sizeof(K_binary) - len);
	}

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

	/* Decrypt the ciphertext from the server */
	plaintext = malloc(32);
	if (plaintext == NULL)
		goto dhx_fail;
	ctxerror = gcry_cipher_decrypt(ctx, plaintext, 32, d, 32);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;
	/* d still points into rbuf.data, which is no longer needed. */
	free(rbuf.data);
	rbuf.data = NULL;

	/* Copy the server's nonce out of the plaintext. */
	memcpy(nonce_binary, plaintext, sizeof(nonce_binary));
	/* Copy the server signature out of the plaintext. NOTE: This will
	 * always contain just 0 values - Apple's docs claim that due to
	 * an error in an early implementation, it will always be that
	 * way - I just ignore it. This could really go away since it's
	 * nonfunctional anyway...
	 */
	memcpy(serverSig, plaintext + sizeof(nonce_binary), sizeof(serverSig));
	free(plaintext);
	plaintext = NULL;

	/* Pull the binary form of the nonce into a form that GMP can
	 * deal with.
	 */
	mpz_import(nonce, sizeof(nonce_binary), 1, 1, 1, 0, nonce_binary);
	/* Increment the nonce by 1 for sending back to the server. */
	mpz_add_ui(new_nonce, nonce, 1);
	/* Pull the incremented nonce value back out into binary form. */
	mpz_export(nonce_binary, &len, 1, 1, 1, 0, new_nonce);
	if (len < sizeof(nonce_binary)) {
		memmove(nonce_binary + (sizeof(nonce_binary) - len),
				nonce_binary, len);
		memset(nonce_binary, 0, sizeof(nonce_binary) - len);
	}
	
	/* New plaintext is 16 bytes of nonce, and (up to) 64 bytes of
	 * password (filled out with NULL values).
	 */
	plaintext = malloc(80);
	if (plaintext == NULL)
		goto dhx_fail;

	memset(plaintext, 0, 80);
	memcpy(plaintext, nonce_binary, sizeof(nonce_binary));
	strncpy(plaintext + sizeof(nonce_binary), passwd, 64);

	/* Set the initialization vector for client->server transfer. */
	ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;

	ai = malloc(80);
	if (ai == NULL)
		goto dhx_fail;
	memset(ai, 0, 80);

	/* Encrypt the plaintext to create our new authinfo block. */
	ctxerror = gcry_cipher_encrypt(ctx, ai, 80, plaintext, 80);
	if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR)
		goto dhx_fail;
	free(plaintext);
	plaintext = NULL;

	/* Send the FPLoginCont with the new authinfo block, sit back,
	 * cross fingers...
	 */
	ret = afp_logincont(server, ID, ai, 80, NULL);

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

#if 0
static int dhx2_login(struct afp_server *server, char *username, char *passwd) {
	char *ai = NULL;
	int ai_len, ret;
	struct afp_rx_buffer rbuf;

	rbuf.data = NULL;

	ai_len = strlen(username + 2);
	ai = malloc(ai_len);
	if (ai == NULL)
		goto dhx2_noctx_fail;
	copy_to_pascal(ai, username);
	if ((strlen(username) + 1) % 2 == 0)
		ai_len--;

	
	ret = afp_login(server, "DHX2", ai, ai_len, &rbuf);
	free(ai);
	ai = NULL;
	if (ret != kFPAuthContinue)
		goto dhx2_noctx_cleanup;


	goto dhx2_cleanup;

dhx2_noctx_fail:
	ret = -1;
	goto dhx2_noctx_cleanup;
dhx2_fail:
	ret = -1;
dhx2_cleanup:
dhx2_noctx_cleanup:
	free(ai);
	free(rbuf.data);
	return ret;
}
#endif

#endif /* HAS_LIBGMP */
#endif /* HAS_LIBGCRYPT */

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

