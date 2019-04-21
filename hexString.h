/*
 *  hexString.h
 *  byteutils
 *
 *  Created by Richard Murphy on 3/7/10.
 *  Copyright 2010 McKenzie-Murphy. All rights reserved.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void hexStringToBytes(uint8_t *outbuf, char *inhex, size_t length);
void bytesToHexString(char * outbuf, uint8_t *bytes, size_t buflen);

