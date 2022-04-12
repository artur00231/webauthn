#pragma once

#include "PublicKey.h"

#include <openssl/evp.h>

namespace webauthn::crypto
{
	class RSAKey : public PublicKey
	{
	public:
		RSAKey(const RSAKey&) = delete;
		RSAKey(RSAKey&&) noexcept;
		RSAKey& operator=(const RSAKey&) = delete;
		RSAKey& operator=(RSAKey&&) noexcept;
		virtual ~RSAKey();

		static std::optional<RSAKey> create(const std::vector<std::byte>& bin_modulus, const std::vector<std::byte>& bin_exponent);

		std::optional<bool> verify(const std::string& data, const std::string& signature) const override;
		std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature) const override;

		void setDefaultHash(COSE::SIGNATURE_HASH hash) noexcept {
			default_hash = hash;
		}

		COSE::SIGNATURE_HASH defaultHash() const noexcept {
			return default_hash;
		}

	protected:
		std::optional<bool> verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size) const;

	private:
		RSAKey() = default;

		EVP_PKEY* p_key{ nullptr };
		COSE::SIGNATURE_HASH default_hash{ COSE::SIGNATURE_HASH::SHA256 };
	};
}

