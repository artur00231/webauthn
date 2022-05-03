#include "Hash.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <limits>

std::array<std::byte, webauthn::crypto::hash_helpers::SHA1_digest_size> webauthn::crypto::hash::SHA1_internal(const std::span<const unsigned char>& data)
{
	std::array<std::byte, hash_helpers::SHA1_digest_size> hash{};

	::SHA1(std::data(data), std::size(data), reinterpret_cast<unsigned char*>(hash.data()));

	return hash;
}

std::array<std::byte, webauthn::crypto::hash_helpers::SHA256_digest_size> webauthn::crypto::hash::SHA256_internal(const std::span<const unsigned char>& data)
{
	std::array<std::byte, hash_helpers::SHA256_digest_size> hash{};

	::SHA256(std::data(data), std::size(data), reinterpret_cast<unsigned char*>(hash.data()));

	return hash;
}

std::array<std::byte, webauthn::crypto::hash_helpers::SHA384_digest_size> webauthn::crypto::hash::SHA384_internal(const std::span<const unsigned char>& data)
{
	std::array<std::byte, hash_helpers::SHA384_digest_size> hash{};

	::SHA384(std::data(data), std::size(data), reinterpret_cast<unsigned char*>(hash.data()));

	return hash;
}

std::array<std::byte, webauthn::crypto::hash_helpers::SHA512_digest_size> webauthn::crypto::hash::SHA512_internal(const std::span<const unsigned char>& data)
{
	std::array<std::byte, hash_helpers::SHA512_digest_size> hash{};

	::SHA512(std::data(data), std::size(data), reinterpret_cast<unsigned char*>(hash.data()));

	return hash;
}

std::vector<std::byte> webauthn::crypto::hash::PBKDF2_internal(const std::span<const char>& passw, const std::span<const unsigned char>& salt, int iteration, int keylen)
{
	std::vector<std::byte> hash{};
	hash.resize(keylen);

	if (std::size(passw) > std::numeric_limits<int>::max() || std::size(salt) > std::numeric_limits<int>::max())
	{
		//Cannot do anything about this
		std::terminate();
	}

	PKCS5_PBKDF2_HMAC(std::data(passw), static_cast<int>(std::size(passw)), std::data(salt), static_cast<int>(std::size(salt)), iteration,
		EVP_sha1(), keylen, reinterpret_cast<unsigned char*>(hash.data()));

	return hash;
}
