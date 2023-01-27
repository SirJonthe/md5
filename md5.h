/// @file
/// @author github.com/SirJonthe
/// @date 2019, 2021, 2022
/// @copyright Public domain. Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.
/// @license BSD-3-Clause

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#ifndef MD5_H_INCLUDED__
#define MD5_H_INCLUDED__

#include <cstdint>
#include <climits>
#include <string>


/// Processes messages of any length into a relatively unique identifyer with a length of 16 bytes. Functions by ingesting any number of messages via the 'ingest' function (alternatively via constructors and () operators) and finally outputting an MD5 sum via the 'digest' function. New messages can be appended even after a digest has been generated.
///
/// @note MD5 can only process a maximum of 2^64-1 bytes (be careful as there is no guard for overflow). This implementation only processes input messages in whole bytes, and can not be used to process messages composed of individual bits.
/// @note MD5 is considered insecure for cryptographic purposes.
class md5
{
private:
	// constants
	static constexpr uint32_t BYTES_PER_DIGEST = 16;
	static constexpr uint32_t WORDS_PER_DIGEST = BYTES_PER_DIGEST / sizeof(uint32_t);
	static constexpr uint32_t BYTES_PER_CHUNK  = 512 / CHAR_BIT;
	static constexpr uint32_t WORDS_PER_CHUNK  = BYTES_PER_CHUNK / sizeof(uint32_t);

public:
	/// The output digest of data after MD5 transformation.
	class sum
	{
		friend class md5;
	private:
		union {
			uint32_t u32[WORDS_PER_DIGEST];
			uint8_t  u8[BYTES_PER_DIGEST];
		} m_sum;
	
	public:
		/// Compares l < r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator< (const sum &r) const;
		/// Compares l > r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator> (const sum &r) const;
		/// Compares l <= r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator<=(const sum &r) const;
		/// Compares l >= r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator>=(const sum &r) const;
		/// Compares l == r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator==(const sum &r) const;
		/// Compares l != r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator!=(const sum &r) const;

		/// Returns the bytes of the digest.
		///
		/// @returns the pointer to the bytes of the digest.
		operator const uint8_t*( void ) const;
		/// Returns the bytes of the digest.
		///
		/// @returns the pointer to the bytes of the digest
		operator uint8_t*( void );

		/// Prints the digest into a human-readable hexadeximal format to a string. 
		///
		/// @param out the destination string of the print.
		///
		/// @returns the pointer to the location in the sprint at which printing stopped.
		char *sprint_hex(char *out) const;
		/// Prints the digest into a human-readable binary format to a string.
		///
		/// @param out the destination string of the print.
		///
		/// @returns the pointer to the location in the sprint at which printing stopped.
		char *sprint_bin(char *out) const;

		/// Returns the human-readable hexadecimal format of the digest.
		///
		/// @returns the human-readable hexadecimal string.
		std::string hex( void ) const;
		/// Returns the human-readable binary format of the digest.
		///
		/// @returns the human-readable hexadecimal string.
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
	/// Bit-block transfer of 64 bytes from 'src' to 'dst'.
	///
	/// @param src the source to write.
	/// @param dst the destination to write to.
	static void blit(const uint8_t *src, uint8_t *dst);
	/// Bit-block transfer of 'num' bytes from 'src' to 'dst'. Fills remaining 64-'num' bytes in 'dst' with zero-value.
	///
	/// @param src the source to write.
	/// @param dst the destination to write to.
	/// @param num the number of bytes to write.
	static void blit(const uint8_t *src, uint8_t *dst, uint32_t num);
	/// Checks if the memory is aligned to a 4-byte boundry.
	///
	/// @param mem the memory location to check for alignment.
	///
	/// @returns boolean indicating true if the memory is 4-byte aligned, and false elsewise.
	static bool is_aligned(const void *mem);
	/// Returns a the left rotation of bits in 'x' by amount 'c'. Bits shifted out are shifted back in from the right.
	///
	/// @param x the data to rotate.
	/// @param c the amount steps to rotate the data.
	///
	/// @returns the rotated data.
	static uint32_t leftrotate(uint32_t x, uint32_t c);
	/// Processes a single message data block and transforms the digest values in 'X'.
	///
	/// @param M pointer to the message block.
	/// @param X pointer to the destination block.
	void process_chunk(const uint32_t *M, uint32_t *X) const;
	/// Processes the remaining data in the block buffer so that a digest can be returned.
	///
	/// @param X the block to do a final transform on.
	void process_final_chunks(uint32_t *X) const;

public:
	/// Default constructor. Sets up the initial internal state.
	md5( void );
	/// Ingest an initial message. Length is inferred from zero-terminator.
	///
	/// @param message pointer to a message to ingest.
	md5(const char *message);
	/// Ingest an initial message. Explicit length.
	///
	/// @param pointer to a message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	md5(const void *message, uint64_t byte_count);
	/// Clear out sensitive data.
	~md5( void );

	/// Default copy constructor.
	md5(const md5&) = default;
	/// Default assingment operator.
	md5 &operator=(const md5&) = default;

	/// Ingest a message. Length is inferred from zero-terminator.
	///
	/// @param message the message to ingest.
	///
	/// @returns a reference to the modified data (self).
	md5 &operator()(const char *message);
	/// Ingest a message. Explicit length.
	///
	/// @param message the message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	///
	/// @returns a reference to the modified data (self).
	md5 &operator()(const void *message, uint64_t byte_count);

	/// Returns a copy of current state with ingested message. Length is inferred from zero-terminator.
	///
	/// @param message the message to ingest.
	///
	/// @returns a modified md5 concorporating the ingestion.
	md5 operator()(const char *message) const;
	/// Returns a copy of current state with ingested message. Explicit length.
	///
	/// @param message the message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	///
	/// @returns a modified md5 concorporating the ingestion.
	md5 operator()(const void *message, uint64_t byte_count) const;

	/// Ingest a message. Length is inferred from zero-terminator.
	///
	/// @param message the message to ingest.
	void ingest(const char *message);
	/// Ingest a message. Explicit length.
	///
	/// @param message the message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	void ingest(const void *message, uint64_t byte_count);

	/// Returns the digest of all ingested messages.
	///
	/// @returns the digest.
	sum digest( void ) const;
	/// Implicitly converts state into digest of all ingested messages.
	///
	/// @returns the digest.
	operator sum( void ) const;
};

/// Returns the MD5 digest of the input message as a human-readable hex string.
///
/// @param message the message to ingest.
///
/// @returns a string containing the human-readable hexadecimal digest of the message.
std::string md5hex(const char *message);
/// Returns the MD5 digest of the input message as a human-readable hex string.
///
/// @param message the message to ingest.
/// @param byte_count the number of bytes in the message to ingest.
///
/// @returns a string containing the human-readable hexadecimal digest of the message.
std::string md5hex(const void *message, uint64_t byte_count);

#endif

