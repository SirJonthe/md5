// md5.cpp
// github.com/SirJonthe
// 2019, 2021, 2022

// Public domain
// Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#include <cstring>
#include "md5.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ENDIAN_BYTES
// Constant to determine endianness of current machine.
const u8 ENDIAN_BYTES[sizeof(u32)] = { 1, 2, 3, 4 };

// is_big
// Determines if the machine endian is big at run-time.
bool is_big( void )
{
	return *reinterpret_cast<const u32*>(ENDIAN_BYTES) == 0x01020304;
}

// is_lil
// Determines if the machine endian is little at run-time.
bool is_lil( void )
{
	return *reinterpret_cast<const u32*>(ENDIAN_BYTES) == 0x4030201;
}

static constexpr u32 CHUNK_BYTESIZE = 512 / CHAR_BIT;

// Table of shift offsets
static constexpr u32 ShiftTable[CHUNK_BYTESIZE] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

// Precomputed table of integer sines (in radians)
static constexpr u32 SineTable[CHUNK_BYTESIZE] = {
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

bool md5::sum::operator<(const md5::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum.u8); ++i) {
		if (m_sum.u8[i] < r.m_sum.u8[i]) {
			return true;
		} else if (m_sum.u8[i] > r.m_sum.u8[i]) {
			return false;
		}
	}
	return false;
}

bool md5::sum::operator>(const md5::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum.u8); ++i) {
		if (m_sum.u8[i] > r.m_sum.u8[i]) {
			return true;
		} else if (m_sum.u8[i] < r.m_sum.u8[i]) {
			return false;
		}
	}
	return false;
}

bool md5::sum::operator<=(const md5::sum &r) const
{
	return (*this == r) || (*this < r);
}

bool md5::sum::operator>=(const md5::sum &r) const
{
	return (*this == r) || (*this > r);
}

bool md5::sum::operator==(const md5::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum.u8); ++i) {
		if (m_sum.u8[i] != r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool md5::sum::operator!=(const md5::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum.u8); ++i) {
		if (m_sum.u8[i] == r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

md5::sum::operator const u8*( void ) const
{
	return m_sum.u8;
}

md5::sum::operator u8*( void )
{
	return m_sum.u8;
}

char *md5::sum::sprint_hex(char *out) const
{
	static constexpr char DIGITS[] = "0123456789abcdef";
	for (u32 i = 0; i < sizeof(m_sum); ++i, out += 2) {
		u8 b = m_sum.u8[i];
		out[0] = DIGITS[b >> 4];
		out[1] = DIGITS[b & 15];
	}
	return out;
}

char *md5::sum::sprint_bin(char *out) const
{
	for (u32 byte = 0; byte < sizeof(m_sum); ++byte) {
		for (u32 bit = 0; bit < CHAR_BIT; ++bit, ++out) {
			out[0] = (m_sum.u8[byte]  & (1 << (CHAR_BIT - 1 - bit))) ? '1' : '0';
		}
	}
	return out;
}

std::string md5::sum::hex( void ) const
{
	static constexpr u64 SIZE = sizeof(m_sum) * 2;
	char str[SIZE];
	memset(str, 0, SIZE);
	sprint_hex(str);
	return std::string(str, size_t(SIZE));
}

std::string md5::sum::bin( void ) const
{
	static constexpr u64 SIZE = sizeof(m_sum) * CHAR_BIT;
	char str[SIZE];
	memset(str, 0, SIZE);
	sprint_bin(str);
	return std::string(str, size_t(SIZE));
}

void md5::blit(const u8 *src, u8 *dst)
{
	memcpy(dst, src, BYTES_PER_CHUNK);
}

void md5::blit(const u8 *src, u8 *dst, u32 num)
{
	memcpy(dst, src, num);
	memset(dst + num, 0, BYTES_PER_CHUNK - num);
}

bool md5::is_aligned(const void *mem)
{
	return (reinterpret_cast<uintptr_t>(mem) & (sizeof(u32) - 1)) != 0;
}

u32 md5::leftrotate(u32 x, u32 c)
{
    return (x << c) | (x >> (32 - c));
}

void md5::process_chunk(const u32 *M, u32 *X) const
{
	enum {a0,b0,c0,d0};

	u32 A = X[a0];
	u32 B = X[b0];
	u32 C = X[c0];
	u32 D = X[d0];
	
	// Process every 64 bytes in chunk.
	for (u32 i = 0; i < BYTES_PER_CHUNK; ++i) {
		u32 F = 0;
		u32 g = 0;
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

void md5::process_final_chunks(u32 *X) const
{

	u64 byte_count = m_chunk_size;
	union {
		u32 w32[WORDS_PER_CHUNK];
		u8  w8[BYTES_PER_CHUNK];
	} chunk;

	// Store size (64 bits) of original message in bits at the end of the message
	u32 padding_size = BYTES_PER_CHUNK - (m_message_size % BYTES_PER_CHUNK);
	if (padding_size < sizeof(u64) + sizeof(u8)) { // Padding must at least fit a 64-bit number to denote message length in bits and one 8-bit number as a terminating 1-bit. If it does not, we add another chunk to process. Note that since we always work on bytes, not bits, the length of the terminating 1-bit is 8 bits, with a value of 0x80.
		padding_size += BYTES_PER_CHUNK;
	}

	// The message will always be padded in some way. Add a first '1' to the padding.
	memcpy(chunk.w8, m_chunk.u8, byte_count);
	chunk.w8[byte_count] = 0x80;
	memset(chunk.w8 + byte_count + 1, 0, BYTES_PER_CHUNK - (byte_count + 1));
	byte_count += padding_size;

	if (byte_count > BYTES_PER_CHUNK) { // Two blocks left to process.
		process_chunk(chunk.w32, X);
		memset(chunk.w8, 0, BYTES_PER_CHUNK - sizeof(u64));
	}

	// One block left to process.
	const u64 ORIGINAL_MESSAGE_BITSIZE = (m_message_size * CHAR_BIT);
	if (is_lil()) {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			chunk.w8[BYTES_PER_CHUNK - sizeof(u64) + i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	} else {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			chunk.w8[BYTES_PER_CHUNK - 1 - i] = reinterpret_cast<const
			char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	}
	process_chunk(chunk.w32, X);
}

md5::md5( void ) : m_message_size(0), m_chunk_size(0)
{
	m_state.u32[0] = 0x67452301; // A
	m_state.u32[1] = 0xefcdab89; // B
	m_state.u32[2] = 0x98badcfe; // C
	m_state.u32[3] = 0x10325476; // D
}

md5::md5(const char *message) : md5()
{
	ingest(message);
}

md5::md5(const void *message, u64 byte_count) : md5()
{
	ingest(message, byte_count);
}

md5::~md5( void )
{
	// Clear sensitive data.
	memset(m_state.u8, 0, sizeof(m_state.u8));
}

md5 &md5::operator()(const char *message)
{
	ingest(message);
	return *this;
}

md5 &md5::operator()(const void *message, u64 byte_count)
{
	ingest(message, byte_count);
	return *this;
}

md5 md5::operator()(const char *message) const
{
	return md5(*this)(message);
}

md5 md5::operator()(const void *message, u64 byte_count) const
{
	return md5(*this)(message, byte_count);
}

void md5::ingest(const char *message)
{
	ingest(message, u64(strlen(message)));
}

void md5::ingest(const void *message, u64 byte_count)
{
	const u8 *msg = reinterpret_cast<const u8*>(message);
	m_message_size += byte_count;
	while (byte_count > 0) {
		u64 bytes_written = 0;
		if (m_chunk_size == 0 && byte_count >= BYTES_PER_CHUNK && is_aligned(msg)) {
			bytes_written = BYTES_PER_CHUNK;
			process_chunk(reinterpret_cast<const u32*>(msg), m_state.u32);
		} else {
			const u64 BYTES_REMAINING = BYTES_PER_CHUNK - m_chunk_size;
			if (byte_count < BYTES_REMAINING) {
				bytes_written = byte_count;
				m_chunk_size += byte_count;
				blit(msg, m_chunk.u8, bytes_written);
			} else {
				bytes_written = BYTES_REMAINING;
				blit(msg, m_chunk.u8, bytes_written);
				process_chunk(m_chunk.u32, m_state.u32);
				m_chunk_size = 0;
			}
		}

		msg += bytes_written;
		byte_count -= bytes_written;
	}
}

md5::sum md5::digest( void ) const
{
	sum out;
	memcpy(out.m_sum.u8, m_state.u8, BYTES_PER_DIGEST);
	process_final_chunks(out.m_sum.u32);
	if (is_big()) { // Convert endianess if necessary - digests should always be in the same format no matter what
		for (u32 i = 0; i < BYTES_PER_DIGEST; i += sizeof(u32)) {
			for (u32 j = 0; j < sizeof(u32) >> 1; ++j) {
				const u32 a = i + j;
				const u32 b = i + sizeof(u32) - j - 1;
				const u8 t = out.m_sum.u8[a];
				out.m_sum.u8[a] = out.m_sum.u8[b];
				out.m_sum.u8[b] = t;
			}
		}
	}
	return out;
}

md5::operator sum( void ) const
{
	return digest();
}

std::string md5hex(const char *message)
{
	return md5(message).digest().hex();
}

std::string md5hex(const void *message, u64 byte_count)
{
	return md5(message, byte_count).digest().hex();
}
