/*
 *  codepage.c
 *
 *  Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2024-2026 Daniel Markstedt <daniel@mindani.net>
 *
 *  These routines handle code page conversions.
 *
 *  Currenly, only UTF8 is supported, but the structure should allow
 *  for classic code pages to be added.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afp_protocol.h"
#include "utils.h"
#include "unicode.h"

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
            *p = ':';  /* Slash in AFP filename becomes colon in Unix */
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
 * This is for converting *from* UTF-8-MAC
 */

int convert_utf8dec_to_utf8pre(char *src, int src_len,
                               char *dest, int dest_len)
{
    char16 *path16dec, c, prev, *p16dec, *p16pre;
    char16 path16pre[384];  /* max 127 * 3 byte UTF8 characters */
    int comp;
    size_t bytes_consumed;
    size_t ucs2_len;

    if (!src || !dest || src_len <= 0 || dest_len <= 0) {
        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    path16dec = UTF8toUCS2(src, src_len, &bytes_consumed);

    if (!path16dec) {
        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    p16dec = path16dec;
    p16pre = path16pre;
    prev = 0;
    ucs2_len = 0;

    while (*p16dec != 0 && ucs2_len < 383) {
        c = *p16dec;

        if (prev > 0) {
            comp = UCS2precompose(prev, c);

            if (comp != -1) {
                /* Keep and try to combine again on next loop */
                prev = (char16)comp;
            } else {
                *p16pre = prev;
                prev = c;
                p16pre++;
                ucs2_len++;
            }
        } else {
            prev = c;
        }

        p16dec++;

        if (*p16dec == 0 && ucs2_len < 383) {
            /* Add last char */
            *p16pre = prev;
            p16pre++;
            ucs2_len++;
        }
    }

    *p16pre = 0; /* Terminate string */

    if (UCS2toUTF8(path16pre, ucs2_len, dest, dest_len) != 0) {
        free(path16dec);

        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    free(path16dec);
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

int convert_utf8pre_to_utf8dec(char *src, int src_len,
                               char *dest, int dest_len)
{
    char16 *path16pre;
    char16 *path16dec, *p16dec;
    const char16 *p16pre;
    size_t ucs2len;
    size_t bytes_consumed;

    if (!src || !dest || src_len <= 0 || dest_len <= 0) {
        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    path16pre = UTF8toUCS2(src, src_len, &bytes_consumed);

    if (!path16pre) {
        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    ucs2len = str16len(path16pre, src_len);
    /* Allocate enough space. Max decomposition expansion is usually small. */
    path16dec = malloc((ucs2len * 4 + 1) * sizeof(char16));

    if (!path16dec) {
        free(path16pre);

        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    p16pre = path16pre;
    p16dec = path16dec;

    while (*p16pre != 0) {
        decompose_char(*p16pre, &p16dec);
        p16pre++;
    }

    *p16dec = 0;

    if (UCS2toUTF8(path16dec, p16dec - path16dec, dest, dest_len) != 0) {
        free(path16pre);
        free(path16dec);

        if (dest && dest_len > 0) {
            *dest = '\0';
        }

        return -1;
    }

    free(path16pre);
    free(path16dec);
    return 0;
}
