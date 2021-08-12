// md5.h
// github.com/SirJonthe
// 2019, 2021

// Public domain
// Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#ifndef MD5_H_INCLUDED__
#define MD5_H_INCLUDED__

#include <cstdint>
#include <string>

// @data md5sum
// @info Container for an MD5 digest. Takes an arbitrary input of bytes (in the form of a string) and converts it into a 16 byte number (or 'digest') representing that input with a fair degree of uniqueness.
class md5sum
{
private:
	uint8_t m_digest[16];

private:
	static void blit(const char *src, char *dst);
	static void blit(const char *src, char *dst, uint32_t num);
	static uint32_t leftrotate(uint32_t x, uint32_t c);
	static void process_chunk(const uint32_t *M, uint32_t *X);

public:
	md5sum( void );
	md5sum(const md5sum&) = default;
	md5sum &operator=(const md5sum&) = default;
	md5sum(const std::string &message);
	md5sum(const char *message, uint64_t byte_count);
	md5sum &operator=(const std::string &message);
	
	// @algo sum
	// @info Generates a digest based on the input and stores it in the container.
	// @in message -> The message to digest.
	void sum(const std::string &message);
	
	// @algo sum
	// @info Generates a digest based on the input and stores it in the container.
	// @in
	//   message -> The message to digest.
	//   byte_count -> The size (in bytes) of the input message.
	void sum(const char *message, uint64_t byte_count);
	
	// @algo hex
	// @inout The digest converted as a human readable hexadecimal ASCII string. Needs to be at least 32 bytes long. Function does not emit null terminator in out string.
	void hex(char *out) const;

	// @algo hex
	// @out The digest converted as a human readable hexadecimal ASCII string.
	std::string hex( void ) const;

	// @algo ==
	// @info Tests for equality between digests.
	// @in Right-hand side MD5 value.
	// @out TRUE on equality.
	bool operator==(const md5sum &r) const;
	
	// @algo !=
	// @info Tests for inequality between digests.
	// @in Right-hand side MD5 value.
	// @out TRUE on inequality.
	bool operator!=(const md5sum &r) const;
	
	// @algo uint8_t*
	// @info Returns the pointer to the digest.
	// @note It is assumed that the user knows the size of 16 bytes.
	// @out The pointer to the digest.
	operator const uint8_t*( void ) const;
};

// @algo md5
// @info Helper function designed to take a message and return its ASCII hex string.
// @in message -> The message to digest.
// @out The ASCII hex string digest.
std::string md5(const std::string &message);

#endif

