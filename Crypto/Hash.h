#pragma once

#include <array>
#include <vector>
#include <cstddef>
#include <concepts>

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

		template<typename T, std::size_t N>
		concept FixedSize = requires(T a)
		{
			std::size(a) == N;
		};

		template<typename T>
		concept Resizeable = requires(T a)
		{
			{ std::declval<T>().resize(std::declval<std::size_t>()) };
		};

		static constexpr std::size_t SHA1_DIGEST_LENGTH = 20;
	}

	template<typename Out = std::array<std::byte, helpers::SHA1_DIGEST_LENGTH>, typename In = std::vector<std::byte>>
	requires helpers::Container<In> && (helpers::FixedSize<Out, helpers::SHA1_DIGEST_LENGTH> || helpers::Resizeable<Out>) &&
		std::default_initializable<Out>&& helpers::Container<Out>
	inline Out SHA1(const In& data)
	{
		Out hash{};

		if constexpr (helpers::Resizeable<Out>)
		{
			hash.resize(helpers::SHA1_DIGEST_LENGTH);
		}

		::SHA1(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<typename Out = std::array<std::byte, SHA256_DIGEST_LENGTH>, typename In = std::vector<std::byte>>
	requires helpers::Container<In> && (helpers::FixedSize<Out, SHA256_DIGEST_LENGTH> || helpers::Resizeable<Out>) &&
		std::default_initializable<Out> && helpers::Container<Out>
	inline Out SHA256(const In& data)
	{
		Out hash{};

		if constexpr (helpers::Resizeable<Out>)
		{
			hash.resize(SHA256_DIGEST_LENGTH);
		}

		::SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<typename Out = std::array<std::byte, SHA384_DIGEST_LENGTH>, typename In = std::vector<std::byte>>
	requires helpers::Container<In> && (helpers::FixedSize<Out, SHA384_DIGEST_LENGTH> || helpers::Resizeable<Out>) &&
		std::default_initializable<Out> && helpers::Container<Out>
	inline Out SHA384(const In& data)
	{
		Out hash{};

		if constexpr (helpers::Resizeable<Out>)
		{
			hash.resize(SHA384_DIGEST_LENGTH);
		}

		::SHA384(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<typename Out = std::array<std::byte, SHA512_DIGEST_LENGTH>, typename In = std::vector<std::byte>>
	requires helpers::Container<In> && (helpers::FixedSize<Out, SHA512_DIGEST_LENGTH> || helpers::Resizeable<Out>) &&
		std::default_initializable<Out>&& helpers::Container<Out>
	inline Out SHA512(const In& data)
	{
		Out hash{};

		if constexpr (helpers::Resizeable<Out>)
		{
			hash.resize(SHA512_DIGEST_LENGTH);
		}

		::SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}

	template<std::size_t N = 64, typename Out = std::array<std::byte, N>, typename In1 = std::vector<std::byte>, typename In2 = std::vector<std::byte>>
	requires helpers::Container<In1> && helpers::Container<In2> && (helpers::FixedSize<Out, N> || helpers::Resizeable<Out>) &&
		std::default_initializable<Out>&& helpers::Container<Out>
	inline Out PBKDF2(const In1& passw, const In2& salt, int iteration = 20000)
	{
		Out hash{};

		if constexpr (helpers::Resizeable<Out>)
		{
			hash.resize(N);
		}

		PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(passw.data()), static_cast<int>(passw.size()), reinterpret_cast<const unsigned char*>(salt.data()),
			static_cast<int>(salt.size()), iteration, N, reinterpret_cast<unsigned char*>(hash.data()));

		return { hash };
	}
}