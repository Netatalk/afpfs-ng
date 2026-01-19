/*
 *  codepage.c
 *
 *  Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
 *
 *  These routines handle code page conversions.
 *
 *  Currenly, only UTF8 is supported, but the structure should allow
 *  for classic code pages to be added.
 *
 */


#include <string.h>
#include <stdlib.h>
#include "afp_protocol.h"
#include "utils.h"
#include "unicode.h"
#include <stdio.h>

int convert_utf8dec_to_utf8pre(char *src, int src_len,
                               char *dest, int dest_len);
int convert_utf8pre_to_utf8dec(char * src, int src_len,
                               char *dest, int dest_len);

/*
 * convert_path_to_unix()
 *
 * This converts an AFP-generated path to Unix's UTF8.  This function
 * does the appropriate encoding lookup.
 */

int convert_path_to_unix(char encoding, char * dest,
                         char *src, int dest_len)
{
    char *p;
    memset(dest, 0, dest_len);

    switch (encoding) {
    case kFPUTF8Name:
        convert_utf8dec_to_utf8pre(src, strlen(src), dest, dest_len);
        break;

    case kFPLongName:
        memcpy(dest, src, dest_len);
        break;

    /* This is where you would put support for other codepages. */
    default:
        return -1;
    }

    /* Convert AFP/Mac path separators back to Unix filename characters
     * This is the reverse of what unixpath_to_afppath() does:
     * - '/' in AFP filenames (which were ':' in Unix) → ':'
     */
    p = dest;

    while (*p && (p < dest + dest_len - 1)) {
        if (*p == '/') {
            *p = ':';  // Slash in AFP filename becomes colon in Unix
        }

        p++;
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
                        char *src, int dest_len)
{
    memset(dest, 0, dest_len);

    switch (encoding) {
    case kFPUTF8Name:
        convert_utf8pre_to_utf8dec(src, strlen(src), dest, dest_len);
        break;

    case kFPLongName:
        memcpy(dest, src, dest_len);
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
 */

/* This is for converting *from* UTF-8-MAC */

int convert_utf8dec_to_utf8pre(char *src, __attribute__((unused)) int src_len,
                               char *dest, __attribute__((unused)) int dest_len)
{
    char16 *path16dec, c, prev, *p16dec, *p16pre;
    char16 path16pre[384];  // max 127 * 3 byte UTF8 characters
    char *pathUTF8pre, *p8pre;
    int comp;
    path16dec = UTF8toUCS2(src);
    p16dec = path16dec;
    p16pre = path16pre;
    prev = 0;

    while (*p16dec > 0) {
        c = *p16dec;

        if (prev > 0) {
            comp = UCS2precompose(prev, c);

            if (comp != -1) {
                prev = (char16)comp;  // Keep and try to combine again on next loop
            } else {
                *p16pre = prev;
                prev = c;
                p16pre++;
            }
        } else {
            prev = c;
        }

        p16dec++;

        if (*p16dec == 0) {		// End of string?
            *p16pre = prev;		// Add last char
            p16pre++;
        }
    }

    *p16pre = 0; // Terminate string
    pathUTF8pre = UCS2toUTF8(path16pre);
    p8pre = pathUTF8pre;

    while (*p8pre) {		// Copy precomposed UTF8 string to dest
        *dest = *p8pre;
        dest++;
        p8pre++;
    }

    *dest = 0;

    if (path16dec) {
        free(path16dec);
    }

    if (pathUTF8pre) {
        free(pathUTF8pre);
    }

    return 0;
}

static void decompose_char(char16 c, char16 **dest)
{
    char16 first, second;

    if (UCS2decompose(c, &first, &second)) {
        decompose_char(first, dest);
        decompose_char(second, dest);
    } else {
        **dest = c;
        (*dest)++;
    }
}

/* convert_utf8pre_to_utf8dec()
 *
 * Conversion for text from Precomposed UTF8 to Decomposed UTF8.
 *
 */

int convert_utf8pre_to_utf8dec(char *src, __attribute__((unused)) int src_len,
                               char *dest, int dest_len)
{
    char16 *path16pre, *p16pre;
    char16 *path16dec, *p16dec;
    char *pathUTF8dec;
    int ucs2len;

    if (!src || !dest || dest_len <= 0) {
        return -1;
    }

    path16pre = UTF8toUCS2(src);

    if (!path16pre) {
        return -1;
    }

    ucs2len = str16len(path16pre);
    /* Allocate enough space. Max decomposition expansion is usually small. */
    path16dec = malloc((ucs2len * 4 + 1) * sizeof(char16));

    if (!path16dec) {
        free(path16pre);
        return -1;
    }

    p16pre = path16pre;
    p16dec = path16dec;

    while (*p16pre) {
        decompose_char(*p16pre, &p16dec);
        p16pre++;
    }

    *p16dec = 0;
    pathUTF8dec = UCS2toUTF8(path16dec);

    if (pathUTF8dec) {
        snprintf(dest, dest_len, "%s", pathUTF8dec);
        free(pathUTF8dec);
    } else {
        *dest = 0;
    }

    free(path16pre);
    free(path16dec);
    return 0;
}
