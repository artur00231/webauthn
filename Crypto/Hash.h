#pragma once

#include <array>
#include <vector>
#include <cstddef>

#include <openssl/sha.h>
#include <openssl/evp.h>

namespace webauthn::crypto::hash
{
	namespace helpers
	{
		template<typename T>
		concept Container = requires(T a)
		{
			{ std::declval<T>().data() };
			{ std::declval<T>().size() } -> std::convertible_to<std::size_t>;
			std::is_convertible_v<typename T::value_type, char>;
		};
	}

	std::array<std::byte, 20> SHA1(const std::vector<std::byte>& data)
	{
		std::array<std::byte, 20> hash{};
		::SHA1(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<typename In = std::vector<std::byte>>
	requires helpers::Container<In>
	std::array<std::byte, SHA256_DIGEST_LENGTH> SHA256(const In& data)
	{
		std::array<std::byte, SHA256_DIGEST_LENGTH> hash{};
		::SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	std::array<std::byte, SHA512_DIGEST_LENGTH> SHA512(const std::vector<std::byte>& data)
	{
		std::array<std::byte, SHA512_DIGEST_LENGTH> hash{};
		::SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<std::size_t N = 64>
	std::array<std::byte, N> PBKDF2(const std::string& passw, const std::vector<std::byte>& salt, int iteration = 20000)
	{
		std::array<std::byte, N> hash{};
		
		PKCS5_PBKDF2_HMAC_SHA1(passw.data(), static_cast<int>(passw.size()), reinterpret_cast<const unsigned char*>(salt.data()), 
			static_cast<int>(salt.size()), iteration, N, reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}
}