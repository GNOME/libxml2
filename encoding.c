/*
 * encoding.c : implements the encoding conversion functions needed for XML
 *
 * Related specs: 
 * rfc2044        (UTF-8 and UTF-16) F. Yergeau Alis Technologies
 * [ISO-10646]    UTF-8 and UTF-16 in Annexes
 * [ISO-8859-1]   ISO Latin-1 characters codes.
 * [UNICODE]      The Unicode Consortium, "The Unicode Standard --
 *                Worldwide Character Encoding -- Version 1.0", Addison-
 *                Wesley, Volume 1, 1991, Volume 2, 1992.  UTF-8 is
 *                described in Unicode Technical Report #4.
 * [US-ASCII]     Coded Character Set--7-bit American Standard Code for
 *                Information Interchange, ANSI X3.4-1986.
 *
 * Original code from "Martin J. Duerst" <duerst@w3.org>
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include "encoding.h"

/*
 * From rfc2044: encoding of the Unicode values on UTF-8:
 *
 * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
 * 0000 0000-0000 007F   0xxxxxxx
 * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
 * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
 *
 * I hope we won't use values > 0xFFFF anytime soon !
 */

/**
 * isolat1ToUTF8:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of ISO Latin 1 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of ISO Latin 1 chars in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
isolat1ToUTF8(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return -1;
            *out++ = c;
        }
        else {
            if (out >= outend)  return -1;
            *out++ = 0xC0 | (c >> 6);
            if (out >= outend)  return -1;
            *out++ = 0x80 | (0x3F & c);
        }
    }
    return out-outstart;
}

/**
 * UTF8Toisolat1:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of UTF-8 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an ISO Latin 1
 * block of chars out.
 * TODO: need a fallback mechanism ...
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8Toisolat1(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return -1;
            *out++= c;
        }
        else if (((c & 0xFE) == 0xC2) && in<inend) {
            if (out >= outend)  return -1;
            *out++= ((c & 0x03) << 6) | (*in++ & 0x3F);
        }
        else  return -2;
    }
    return out-outstart;
}

/**
 * UTF16ToUTF8:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of UTF-16 chars (array of unsigned shorts)
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-16 ushorts in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
UTF16ToUTF8(unsigned char* out, int outlen, unsigned short* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned short* inend= in+inlen;
    unsigned int c, d;
    int bits;

    while (in < inend) {
        c= *in++;
        if ((c & 0xFC00) == 0xD800) {    /* surrogates */
            if ((in<inend) && (((d=*in++) & 0xFC00) == 0xDC00)) {
                c &= 0x03FF;
                c <<= 10;
                c |= d & 0x03FF;
                c += 0x10000;
            }
            else  return -1;
        }

      /* assertion: c is a single UTF-4 value */

        if (out >= outend)  return -1;
        if      (c <    0x80) {  *out++=  c;                bits= -6; }
        else if (c <   0x800) {  *out++= (c >>  6) | 0xC0;  bits=  0; }
        else if (c < 0x10000) {  *out++= (c >> 12) | 0xE0;  bits=  6; }
        else                  {  *out++= (c >> 18) | 0xF0;  bits= 12; }
 
        for ( ; bits < 0; bits-= 6) {
            if (out >= outend)  return -1;
            *out++= (c >> bits) & 0x3F;
        }
    }
    return out-outstart;
}

/**
 * UTF8ToUTF16:
 * @out:  a pointer ot an array of shorts to store the result
 * @outlen:  the lenght of @out (number of shorts)
 * @in:  a pointer ot an array of UTF-8 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an UTF-16
 * block of chars out.
 * TODO: need a fallback mechanism ...
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8ToUTF16(unsigned short* out, int outlen, unsigned char* in, int inlen)
{
    unsigned short* outstart= out;
    unsigned short* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned int c, d, trailing;

    while (in < inend) {
      d= *in++;
      if      (d < 0x80)  { c= d; trailing= 0; }
      else if (d < 0xC0)  return -2;    /* trailing byte in leading position */
      else if (d < 0xE0)  { c= d & 0x1F; trailing= 1; }
      else if (d < 0xF0)  { c= d & 0x0F; trailing= 2; }
      else if (d < 0xF8)  { c= d & 0x07; trailing= 3; }
      else return -2;    /* no chance for this in UTF-16 */

      for ( ; trailing; trailing--) {
          if ((in >= inend) || (((d= *in++) & 0xC0) != 0x80))  return -1;
          c <<= 6;
          c |= d & 0x3F;
      }

      /* assertion: c is a single UTF-4 value */
        if (c < 0x10000) {
            if (out >= outend)  return -1;
            *out++ = c;
        }
        else if (c < 0x110000) {
            if (out+1 >= outend)  return -1;
            c -= 0x10000;
            *out++ = 0xD800 | (c >> 10);
            *out++ = 0xDC00 | (c & 0x03FF);
        }
        else  return -1;
    }
    return out-outstart;
}


