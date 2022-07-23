// md5.h
// github.com/SirJonthe
// 2019, 2021, 2022

// Public domain
// Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#ifndef MD5_H_INCLUDED__
#define MD5_H_INCLUDED__

#include <cstdint>
#include <climits>
#include <string>

// md5
// Processes messages of any length into a relatively unique identifyer with a length of 16 bytes. Functions by ingesting any number of messages via the 'ingest' function (alternatively via constructors and () operators) and finally outputting an MD5 sum via the 'digest' function. New messages can be appended even after a digest has been generated.
// LIMITATIONS: MD5 can only process a maximum of 2^64-1 bytes (be careful as there is no guard for overflow). This implementation only processes input messages in whole bytes, and can not be used to process messages composed of individual bits.
// SECURITY NOTE: MD5 is considered insecure for cryptographic purposes.
class md5
{
private:
	// constants
	static constexpr uint32_t BYTES_PER_DIGEST = 16;
	static constexpr uint32_t WORDS_PER_DIGEST = BYTES_PER_DIGEST / sizeof(uint32_t);
	static constexpr uint32_t BYTES_PER_CHUNK  = 512 / CHAR_BIT;
	static constexpr uint32_t WORDS_PER_CHUNK  = BYTES_PER_CHUNK / sizeof(uint32_t);

public:
	// sum
	// The output digest of data after MD5 transformation.
	class sum
	{
		friend class md5;
	private:
		union {
			uint32_t u32[WORDS_PER_DIGEST];
			uint8_t  u8[BYTES_PER_DIGEST];
		} m_sum;
	
	public:
		// operator<
		// Compares l < r.
		bool operator< (const sum &r) const;
		// operator>
		// Compares l > r.
		bool operator> (const sum &r) const;
		// operator<=
		// Compares l <= r.
		bool operator<=(const sum &r) const;
		// operator>=
		// Compares l >= r.
		bool operator>=(const sum &r) const;
		// operator==
		// Compares l == r.
		bool operator==(const sum &r) const;
		// operator!=
		// Compares l != r.
		bool operator!=(const sum &r) const;

		// operator const uint8_t*
		// Returns the bytes of the digest.
		operator const uint8_t*( void ) const;
		// operator uint8_t*
		// Returns the bytes of the digest.
		operator uint8_t*( void );

		// sprint_hex
		// Prints the digest into a human-readable hexadeximal format stored in 'out' and returns 'out' incremented by the number of characters written. 
		char *sprint_hex(char *out) const;
		// sprint_bin
		// Prints the digest into a human-readable binary format stored in 'out' and returns 'out' incremented by the number of characters written.
		char *sprint_bin(char *out) const;

		// hex
		// Returns the human-readable hexadecimal format of the digest.
		std::string hex( void ) const;
		// bin
		// Returns the human-readable binary format of the digest.
		std::string bin( void ) const;
	};

private:
	union {
		uint32_t u32[WORDS_PER_DIGEST];
		uint8_t  u8[BYTES_PER_DIGEST];
	} m_state;
	union {
		uint32_t u32[WORDS_PER_CHUNK];
		uint8_t  u8[BYTES_PER_CHUNK];
	} m_chunk;
	uint64_t m_message_size;
	uint32_t m_chunk_size;

private:
	// blit
	// Bit-block transfer of 64 bytes from 'src' to 'dst'.
	static void blit(const uint8_t *src, uint8_t *dst);
	// blit
	// Bit-block transfer of 'num' bytes from 'src' to 'dst'. Fills remaining 64-'num' bytes in 'dst' with zero-value.
	static void blit(const uint8_t *src, uint8_t *dst, uint32_t num);
	// is_aligned
	// Checks if the memory is aligned to a 4-byte boundry.
	static bool is_aligned(const void *mem);
	// leftrotate
	// Returns a the left rotation of bits in 'x' by amount 'c'. Bits shifted out are shifted back in from the right.
	static uint32_t leftrotate(uint32_t x, uint32_t c);
	// process_chunk
	// Processes a single message data block and transforms the digest values in 'X'.
	void process_chunk(const uint32_t *M, uint32_t *X) const;
	// process_final_chunks
	// Processes the remaining data in the block buffer so that a digest can be returned.
	void process_final_chunks(uint32_t *X) const;

public:
	// md5
	// Default constructor. Sets up the initial internal state.
	md5( void );
	// md5
	// Ingest an initial message. Length is inferred from zero-terminator.
	md5(const char *message);
	// md5
	// Ingest an initial message. Explicit length.
	md5(const void *message, uint64_t byte_count);
	// ~md5
	// Clear out sensitive data.
	~md5( void );

	// md5
	// Default copy constructor.
	md5(const md5&) = default;
	// operator=
	// Default assingment operator.
	md5 &operator=(const md5&) = default;

	// operator()
	// Ingest a message. Length is inferred from zero-terminator.
	md5 &operator()(const char *message);
	// operator()
	// Ingest a message. Explicit length.
	md5 &operator()(const void *message, uint64_t byte_count);

	// operator() const
	// Returns a copy of current state with ingested message. Length is inferred from zero-terminator.
	md5 operator()(const char *message) const;
	// operator() const
	// Returns a copy of current state with ingested message. Explicit length.
	md5 operator()(const void *message, uint64_t byte_count) const;

	// ingest
	// Ingest a message. Length is inferred from zero-terminator.
	void ingest(const char *message);
	// ingest
	// Ingest a message. Explicit length.
	void ingest(const void *message, uint64_t byte_count);

	// digest
	// Returns the digest of all ingested messages.
	sum digest( void ) const;
	// operator digest
	// Implicitly converts state into digest of all ingested messages.
	operator sum( void ) const;
};

// md5hex
// Returns the MD5 digest of the input message as a human-readable hex string.
std::string md5hex(const char *message);
// md5hex
// Returns the MD5 digest of the input message as a human-readable hex string.
std::string md5hex(const void *message, uint64_t byte_count);

#endif

