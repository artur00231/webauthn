#pragma once

#include "PublicKey.h"

#include <optional>
#include <vector>
#include <string>

#include <openssl/ec.h>

namespace webauthn::crypto
{
	enum class ECDSA_EC { P256 = 1, P384 = 2, P521 = 3, secp256k1 = 8 };

	class ECDSAKey : public PublicKey
	{
	public:
		ECDSAKey(const ECDSAKey&) = delete;
		ECDSAKey(ECDSAKey&&) noexcept;
		ECDSAKey& operator=(const ECDSAKey&) = delete;
		ECDSAKey& operator=(ECDSAKey&&) noexcept;
		~ECDSAKey();

		static std::optional<ECDSAKey> create(const std::string& hex_x, const std::string& hex_y, const ECDSA_EC ec);

		std::optional<bool> verify(const std::string& data, const std::string& signature, const SIGNATURE_HASH hash) const override;
		std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const SIGNATURE_HASH hash) const override;

	protected:
		std::optional<bool> verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size,
			const SIGNATURE_HASH hash) const;

	private:
		ECDSAKey() = default;

		EC_KEY* eckey{ nullptr };
	};
}

