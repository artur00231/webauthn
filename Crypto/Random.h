#pragma once 

#include <utility>
#include <cstddef>
#include <array>
#include <vector>
#include <optional>

#include <openssl/rand.h>

namespace webauthn::crypto::random
{
	template<std::size_t N>
	inline std::optional<std::array<std::byte, N>> genRandom()
	{
		std::array<std::byte, N> bytes{};
		int rc = RAND_bytes(reinterpret_cast<unsigned char*>(bytes.data()), static_cast<int>(bytes.size()));

		if (rc != 1)
		{
			return {};
		}

		return { bytes };
	}

	inline std::optional<std::vector<std::byte>> genRandom(std::size_t size)
	{
		std::vector<std::byte> bytes{};
		bytes.resize(size);
		int rc = RAND_bytes(reinterpret_cast<unsigned char*>(bytes.data()), static_cast<int>(bytes.size()));

		if (rc != 1)
		{
			return {};
		}

		return { bytes };
	}
}