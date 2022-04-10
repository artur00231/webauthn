#pragma once

#include "PublicKey.h"
#include "COSE.h"

#include <optional>
#include <vector>
#include <string>

#include <openssl/evp.h>

namespace webauthn::crypto
{
	class EdDSAKey : public PublicKey
	{
	public:
		EdDSAKey(const EdDSAKey&) = delete;
		EdDSAKey(EdDSAKey&&) noexcept;
		EdDSAKey& operator=(const EdDSAKey&) = delete;
		EdDSAKey& operator=(EdDSAKey&&) noexcept;
		virtual ~EdDSAKey();

		static std::optional<EdDSAKey> create(const std::vector<std::byte>& bin_x, const COSE::EdDSA_EC ec);

		std::optional<bool> verify(const std::string& data, const std::string& signature) const override;
		std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature) const override;

	protected:
		std::optional<bool> verify(const unsigned char* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size) const;

	private:
		EdDSAKey() = default;

		EVP_PKEY* pkey{ nullptr };
	};
}

