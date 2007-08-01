
/*
 *  codepage.c
 *
 *  Copyright (C) 2007 Alex deVries
 *
 *  These routines handle code page conversions.
 *
 *  Currenly, only UTF8 is supported, but the structure should allow
 *  for classic code pages to be added.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "afp_protocol.h"
#include "utils.h"

int convert_utf8dec_to_utf8pre(const char *src, int src_len,
	char * dest, int dest_len);
int convert_utf8pre_to_utf8dec(const char * src, int src_len, 
	char * dest, int dest_len);

/* 
 * convert_path_to_unix()
 *
 * This converts an AFP-generated path to Unix's UTF8.  This function
 * does the appropriate encoding lookup.
 */

int convert_path_to_unix(char encoding, char * dest, 
	char * src, unsigned char dest_len)
{

	bzero(dest,dest_len);

	switch (encoding) {
	case kFPUTF8Name:
		convert_utf8dec_to_utf8pre(src, strlen(src), dest, dest_len);
		break;
	case kFPLongName:
		return -1;
		break;
	/* This is where you would put support for other codepages. */
	default:
		return -1;
	}
	return 0;
}

/* 
 * convert_path_to_afp()
 *
 * Given a null terminated source, converts the path to an AFP path
 * given the encoding.
 */

int convert_path_to_afp(char encoding, char * dest, 
	char * src, int dest_len)
{
	unsigned char namelen;

	bzero(dest,dest_len);

	switch (encoding) {
	case kFPUTF8Name: 
		namelen=convert_utf8pre_to_utf8dec(src, strlen(src),
			dest,dest_len);
		break;
	case kFPLongName:
		bcopy(src,dest,dest_len);
		break;
	/* This is where you would put support for other codepages. */
	default:
		return -1;
	}
	return 0;
}

/* convert_utf8dec_to_utf8pre()
 *
 * Conversion for text from Decomposed UTF8 used in AFP to Precomposed
 * UTF8 used elsewhere.
 *
 * This is a sample conversion.  The only translation it does is on one 
 * sequence of characters (0x61 0xcc 0x88 becomes 0xc3 0xa4).
 *
 * Fix this.
 */

/* This is for converting *from* UTF-8-MAC */

int convert_utf8dec_to_utf8pre(const char *src, int src_len,
	char * dest, int dest_len)
{
	int i, j=0;
	for (i=0;i<src_len; i++) {
		if (((src[i] & 0xff)==0x61) && ((src[i+1] & 0xff)==0xcc) &&
			((src[i+2] & 0xff)==0x88)) {
			dest[j]=0xc3;
			j++;
			dest[j]=0xa4;
			j++;
			i+=2;
		} else {
			dest[j]=src[i];
			j++;
		}

	}
	return j;

}

/* convert_utf8pre_to_utf8dec()
 *
 * Conversion for text from Precomposed UTF8 to Precomposed UTF8.
 *
 * This is a sample conversion.  The only translation it does is on one 
 * sequence of characters (0xc3 0xa4 becomes 0x61 0xcc 0x88).
 *
 * Fix this.
 */

int convert_utf8pre_to_utf8dec(const char * src, int src_len, 
	char * dest, int dest_len)
{
	int i, j=0;
	for (i=0;i<src_len; i++) {
		if (((src[i] & 0xff)==0xc3) && ((src[i+1] & 0xff)==0xa4)) {
			dest[j]=0x61;
			j++;
			dest[j]=0xcc;
			j++;
			dest[j]=0x88;
			i++;
		} else 
			dest[j]=src[i];
		j++;

	}
	return j;
}

