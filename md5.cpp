// md5.cpp
// github.com/SirJonthe
// 2019, 2021

// Public domain
// Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#include <cstring>
#include <climits>
#include "md5.h"

static constexpr uint32_t CHUNK_BYTESIZE = 512 / CHAR_BIT;

// Table of shift offsets
static constexpr uint32_t ShiftTable[CHUNK_BYTESIZE] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

// Precomputed table of integer sines (in radians)
static constexpr uint32_t SineTable[CHUNK_BYTESIZE] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

md5sum::md5sum( void )
{
	for (uint32_t i = 0; i < 16; ++i) {
		m_digest[i] = 0;
	}
}

md5sum::md5sum(const std::string &message)
{
	sum(message);
}

md5sum::md5sum(const char *message, uint64_t byte_count)
{
	sum(message, byte_count);
}

md5sum &md5sum::operator=(const std::string &message)
{
	sum(message);
	return *this;
}

void md5sum::blit(const char *src, char *dst)
{
	memcpy(dst, src, CHUNK_BYTESIZE);
}

void md5sum::blit(const char *src, char *dst, uint32_t num)
{
	memcpy(dst, src, num);
	memset(dst + num, 0, CHUNK_BYTESIZE - num);
}

uint32_t md5sum::leftrotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

void md5sum::process_chunk(const uint32_t *M, uint32_t *X)
{
	enum {a0,b0,c0,d0};

	uint32_t A = X[a0];
	uint32_t B = X[b0];
	uint32_t C = X[c0];
	uint32_t D = X[d0];
	
	// Process every 64 bytes in chunk.
	for (uint32_t i = 0; i < CHUNK_BYTESIZE; ++i) {
		uint32_t F = 0;
		uint32_t g = 0;
		if (i < 16) {
			F = (B & C) | ((~B) & D);
			g = i;
		} else if (i < 32) {
			F = (D & B) | ((~D) & C);
			g = (5*i + 1) % 16;
		} else if (i < 48) {
			F = B ^ C ^ D;
			g = (3*i + 5) % 16;
		} else {
			F = C ^ (B | (~D));
			g = (7*i) % 16;
		}
		
		F = F + A + SineTable[i] + M[g];
		A = D;
		D = C;
		C = B;
		B += leftrotate(F, ShiftTable[i]);
	}
	
	// Add to result.
	X[a0] += A;
	X[b0] += B;
	X[c0] += C;
	X[d0] += D;
}

void md5sum::sum(const std::string &message)
{
	sum(message.c_str(), uint64_t(message.size()));
}

void md5sum::sum(const char *message, uint64_t byte_count)
{
	// Aligned temporary buffer.
	char chunk[CHUNK_BYTESIZE];

	// Initialization.
	uint32_t *X = reinterpret_cast<uint32_t*>(m_digest);
	enum {a0,b0,c0,d0};
	X[a0] = 0x67452301; // A
	X[b0] = 0xefcdab89; // B
	X[c0] = 0x98badcfe; // C
	X[d0] = 0x10325476; // D

	// Compute padding.
	const uint64_t ORIGINAL_MESSAGE_SIZE = byte_count;

	// Process every 512-bit chunk, except for partial or last one.
	const uint32_t *M = nullptr;
	
	if ((reinterpret_cast<const uintptr_t>(message) & (sizeof(uint32_t) * CHAR_BIT - 1)) != 0) { // The message is not aligned so we need to bit block transfer it to an aligned block before processing (mainly to ensure functioning on ARM processors).
		M = reinterpret_cast<const uint32_t*>(chunk);
		while (byte_count >= CHUNK_BYTESIZE) {
			blit(message, chunk);
			process_chunk(M, X);
			message += CHUNK_BYTESIZE;
			byte_count -= CHUNK_BYTESIZE;
		}
	} else { // The message is aligned so we can process it directly without aligning it manually.
		M = reinterpret_cast<const uint32_t*>(message);
		constexpr uint32_t CHUNK_WORDSIZE = CHUNK_BYTESIZE / sizeof(uint32_t);
		while (byte_count >= CHUNK_BYTESIZE) {
			process_chunk(M, X);
			message += CHUNK_BYTESIZE;
			byte_count -= CHUNK_BYTESIZE;
			M += CHUNK_WORDSIZE;
		}
		M = reinterpret_cast<const uint32_t*>(chunk);
	}

	// The last chunk always needs to be processed manually since it always contains message size.
	blit(message, chunk, byte_count);

	// Store size (64 bits) of original message in bits at the end of the message
	uint32_t padding_size = CHUNK_BYTESIZE - (ORIGINAL_MESSAGE_SIZE % CHUNK_BYTESIZE);
	if (padding_size < sizeof(uint64_t) + sizeof(uint8_t)) { // Padding must at least fit a 64-bit number to denote message length in bits and one 8-bit number as a terminating 1-bit. If it does not, we add another chunk to process. Note that since we always work on bytes, not bits, the length of the terminating 1-bit is 8 bits, with a value of 0x80.
		padding_size += CHUNK_BYTESIZE;
	}

	// The message will always be padded in some way. Add a first '1' to the padding.
	chunk[byte_count] = 0x80;
	byte_count += padding_size;

	if (byte_count > CHUNK_BYTESIZE) { // Two blocks left to process.
		process_chunk(M, X);
		byte_count -= CHUNK_BYTESIZE;
		memset(chunk, 0, CHUNK_BYTESIZE - sizeof(uint64_t));
	}

	// One block left to process.
	const uint64_t ORIGINAL_MESSAGE_BITSIZE = (ORIGINAL_MESSAGE_SIZE * CHAR_BIT);
	for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
		chunk[CHUNK_BYTESIZE - sizeof(uint64_t) + i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
	}
	process_chunk(M, X);
	byte_count -= CHUNK_BYTESIZE;

	// Clear sensitive data.
	memset(chunk, 0, CHUNK_BYTESIZE);
}

void md5sum::hex(char *out) const
{
	for (uint32_t i = 0; i < 16; ++i) {
		sprintf(out, "%02x", m_digest[i]);
		out += 2;
	}
}

std::string md5sum::hex( void ) const
{
	char out[33];
	hex(out);
	out[32] = '\0';
	return std::string(out, 32);
}

bool md5sum::operator==(const md5sum &r) const
{
	for (uint32_t i = 0; i < 16; ++i) {
		if (m_digest[i] != r.m_digest[i]) { return false; }
	}
	return true;
}

bool md5sum::operator!=(const md5sum &r) const
{
	for (uint32_t i = 0; i < 16; ++i) {
		if (m_digest[i] == r.m_digest[i]) { return false; }
	}
	return true;
}

md5sum::operator const uint8_t*( void ) const
{
	return m_digest;
}

std::string md5(const std::string &message)
{
	return md5sum(message).hex();
}
