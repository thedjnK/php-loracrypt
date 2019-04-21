/*
 *  hexString.c
 *  byteutils
 *
 *  Created by Richard Murphy on 3/7/10.
 *  Copyright 2010 McKenzie-Murphy. All rights reserved
 *
 *  Modified by thedjnK (2018) for use in php-loracrypt
 *
 */

#include "hexString.h"

/* utility function to convert hex character representation to their nibble (4 bit) values */
static uint8_t nibbleFromChar(char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 255;
}

/* Convert a string of characters representing a hex buffer into a series of bytes of that real value */
void hexStringToBytes(uint8_t *outbuf, char *inhex, size_t length)
{
    uint8_t *p;
    int len, i;
	
    len = length / 2;
    for (i=0, p = (uint8_t *) inhex; i<len; i++)
    {
        outbuf[i] = (nibbleFromChar(*p) << 4) | nibbleFromChar(*(p+1));
        p += 2;
    }
    outbuf[len] = 0;
}

static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static int byteMapLen = sizeof(byteMap);

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
static char nibbleToChar(uint8_t nibble)
{
    if(nibble < byteMapLen) return byteMap[nibble];
    return '*';
}

/* Convert a buffer of binary values into a hex string representation */
void bytesToHexString(char * outbuf, uint8_t *bytes, size_t buflen)
{
    int i;	
    for(i=0; i<buflen; i++)
    {
        outbuf[i*2] = nibbleToChar(bytes[i] >> 4);
        outbuf[i*2+1] = nibbleToChar(bytes[i] & 0x0f);
    }
    outbuf[i] = '\0';
}
