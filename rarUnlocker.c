/*
 * Copyright )C( 2019 AHOHNMYC
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 */

#include <stdbool.h> // bool type, true, false
#include <stdint.h>  // uintXX_t-like types
#include <stdio.h>   // printf, file IO
#include <stdlib.h>  // calloc
#include <string.h>  // memcmp

#define usage "Usage:\trarUnlocker [-l] <archive.rar>\n\
\n\
 -l\t- lock archive\n\
\n\
\t(c) AHOHNMYC, 2o19\n"

uint32_t crc32_for_byte(uint32_t r);
uint32_t crc32(const void* data, size_t n_bytes);

// Returns vintLen, count of bytes ocupied by this vint
int vint(uint8_t* buf, uint32_t* vintOut);

#define RAR4   4
#define RAR5   5

#define CRC_START4    7
#define CRC_START5    8
#define CRC_LENGTH4   2
#define CRC_LENGTH5   4
#define HEADER_START4 (CRC_START4 + CRC_LENGTH4)
#define HEADER_START5 (CRC_START5 + CRC_LENGTH5)
#define LOCKED_FLAG_MASK4 0x04
#define LOCKED_FLAG_MASK5 0x10

#define HEADER_TYPE_LENGTH4     1
#define HEADER_LENGTH4          0xB
#define ENCRYPTED_HEADER_TYPE5  4
#define EXTRA_DATA_HEADER_FLAG5 0x1

#define BUFFER_SIZE 1<<8
#define FLAG_LENGTH 1

static const uint8_t rar4sig[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};        // RAR2-4 signature
static const uint8_t rar5sig[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};  // RAR5   signature

int main(int argc, char** argv) {
	bool doLock = false;
	int fileArg = 1;
	
	// I know, I know...
	if (argc == 3) {
		if (memcmp(argv[1], "-l", 2) == 0) {
			doLock = true;
			fileArg = 2;
		} else if (memcmp(argv[2], "-l", 2) == 0) {
			doLock = true;
		} else {
			printf(usage);
			return 1;
		}
	} else if (argc != 2) {
		printf(usage);
		return 1;
	}
	
	FILE* file = fopen(argv[fileArg], "r+b");
	if (file == NULL) {
		perror("Error opening file");
		return 1;
	}
	
	uint8_t* buf = calloc(BUFFER_SIZE, sizeof(*buf));
	
	unsigned int readBytes = fread(buf, sizeof(*buf), BUFFER_SIZE, file);
	if (readBytes == 0) {
		perror("Error reading file");
		return 1;
	}

	unsigned int type;
	
	if (memcmp(buf, rar5sig, sizeof(rar5sig)) == 0) {
		type = RAR5;
	} else if (memcmp(buf, rar4sig, sizeof(rar4sig)) == 0) {
		type = RAR4;
	} else {
		fprintf(stderr, "This is not RAR file!\n");
		return 1;
	}


	void* pCrc;
	uint8_t* pData; // Data - all that have to be CRC-ed
	unsigned int dataLen;
	uint8_t* pFlag;
	uint8_t lockFlagMask;
	long writeByteStart;
	unsigned int writeByteCount;
	
	if (type == RAR5) {
		pCrc    = buf + CRC_START5;
		pData   = buf + HEADER_START5;
		unsigned int headerSize;
		unsigned int headerSizeLen = vint(pData, &headerSize);
		unsigned int headerType;
		unsigned int headerTypeLen = vint(pData+headerSizeLen, &headerType);
		unsigned int headerFlag;
		unsigned int headerFlagLen = vint(pData+headerSizeLen+headerTypeLen, &headerFlag);

		if (headerType == ENCRYPTED_HEADER_TYPE5) {
			fprintf(stderr, "RAR5 files with encrypted headers are not supported!\n");
			return 1;
		}

		unsigned int flagOffset = headerSizeLen + headerTypeLen + headerFlagLen;

		if ((headerFlag&EXTRA_DATA_HEADER_FLAG5) != 0) // Optional field "Extra area size"
			flagOffset += vint(pData+flagOffset, NULL); // Add length of this field, if it presents

		dataLen        = headerSizeLen + headerSize;
		pFlag          = pData + flagOffset;
		lockFlagMask   = LOCKED_FLAG_MASK5;
		writeByteStart = CRC_START5;
		writeByteCount = CRC_LENGTH5 + flagOffset + FLAG_LENGTH;
	} else {
		pCrc           = buf + CRC_START4;
		pData          = buf + HEADER_START4;
		dataLen        = HEADER_LENGTH4;
		pFlag          = pData + HEADER_TYPE_LENGTH4;
		lockFlagMask   = LOCKED_FLAG_MASK4;
		writeByteStart = CRC_START4;
		writeByteCount = CRC_LENGTH4 + HEADER_TYPE_LENGTH4 + FLAG_LENGTH; // Always 4
	}
	
	// Here we are trying to check CRC of header.
	// Maybe it's tooo ooold version? We don't want to corrupt unknown files~
	// Calculating original CRC...
	uint32_t oldCrc = crc32(pData, dataLen);
	bool isHeaderCrcValid;
	// Comparing calculated CRC and header CRC
	if (type == RAR5)
		isHeaderCrcValid = *(uint32_t*)pCrc == oldCrc;
	else
		isHeaderCrcValid = *(uint16_t*)pCrc == (uint16_t)oldCrc;

	if (!isHeaderCrcValid) {
		fprintf(stderr, "File is corrupted or not supported!\n");
		return 1;
	}

	bool lockedFlag = (*pFlag&lockFlagMask) != 0;

	if (lockedFlag == doLock) {
		printf("Archive is %s locked :3\n", doLock ? "already" : "not");
		return 0;
	}

	if (doLock)	
		*pFlag |= lockFlagMask;
	else
		*pFlag &= ~lockFlagMask;
	printf("Lock flag %ssetted\n", doLock ? "" : "un");
	
	// Calculating CRC...
	uint32_t newCrc = crc32(pData, dataLen);
	
	// Writing CRC
	if (type == RAR5)
		*(uint32_t*)pCrc = newCrc;
	else
		*(uint16_t*)pCrc = (uint16_t)newCrc;

	fseek(file, writeByteStart, SEEK_SET);
	if (writeByteCount != fwrite(pCrc, sizeof(uint8_t), writeByteCount, file)) {
		perror("Error writing file");
		return 1;
	}
	
	printf("Archive had been %slocked ;3\n", doLock ? "" : "un");
	return 0;
}

int vint(uint8_t* buf, uint32_t* vintOut) {
	int vintLen = 0;
	uint32_t vint = 0;
	do {
		vint <<= 7;
		vint |= *buf & ~0x80u;
		vintLen++;
	} while (*buf++ >> 7u);
	if (vintOut != NULL)
		*vintOut = vint; 
	return vintLen;
}


// http://home.thep.lu.se/~bjorn/crc/crc32_simple.c
// Bjorn Samuelsson, public domain
// Some modifications are done to minimize footprint
inline uint32_t crc32_for_byte(uint32_t r) {
	for(int j = 0; j < 8; ++j)
		r = (r & 1? 0: (uint32_t)0xEDB88320Lu) ^ r >> 1;
	return r ^ (uint32_t)0xFF000000L;
}
inline uint32_t crc32(const void* data, size_t n_bytes) {
	uint32_t crc = 0;
	for(size_t i = 0; i < n_bytes; ++i)
		crc = crc32_for_byte((uint8_t)crc ^ ((uint8_t*)data)[i]) ^ crc >> 8u;
	return crc;
}
