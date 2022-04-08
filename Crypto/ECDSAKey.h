#pragma once

#include "PublicKey.h"
#include "COSE.h"

#include <optional>
#include <vector>
#include <string>

#include <openssl/ec.h>

namespace webauthn::crypto
{
	class ECDSAKey : public PublicKey
	{
	public:
		ECDSAKey(const ECDSAKey&) = delete;
		ECDSAKey(ECDSAKey&&) noexcept;
		ECDSAKey& operator=(const ECDSAKey&) = delete;
		ECDSAKey& operator=(ECDSAKey&&) noexcept;
		virtual ~ECDSAKey();

		static std::optional<ECDSAKey> create(const std::vector<std::byte>& bin_x, const std::vector<std::byte>& bin_y, const COSE::ECDSA_EC ec);

		std::optional<bool> verify(const std::string& data, const std::string& signature, const COSE::SIGNATURE_HASH hash) const override;
		std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const COSE::SIGNATURE_HASH hash) const override;

		void setDefaultHash(COSE::SIGNATURE_HASH hash) noexcept {
			default_hash = hash;
		}

		COSE::SIGNATURE_HASH defaultHash() const noexcept {
			return default_hash;
		}

	protected:
		std::optional<bool> verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size,
			const COSE::SIGNATURE_HASH hash) const;

	private:
		ECDSAKey() = default;

		EC_KEY* eckey{ nullptr };
		COSE::SIGNATURE_HASH default_hash{ COSE::SIGNATURE_HASH::SHA256 };
	};
}

