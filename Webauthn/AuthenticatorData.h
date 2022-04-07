#pragma once

#include <array>
#include <vector>
#include <cstddef>
#include <optional>
#include <memory>

#include "CredentialId.h"

#include "../Crypto/PublicKey.h"

namespace webauthn
{
	class PublicKey
	{
	public:
		std::vector<std::byte> public_key_cbor{};

		std::unique_ptr<crypto::PublicKey> public_key{ nullptr };
	};

	class AttestedCredentialData
	{
	public:
		std::array<std::byte, 16> AAGUID{};
		CredentialId credential_id{};
		//Public key

		std::optional<PublicKey> key{};
	};

	class AuthenticatorData
	{
	public:
		//SHA-256 of RelyingParty id
		std::array<std::byte, 32> RP_ID_hash{};

		bool user_present{};
		bool user_verified{};
		std::uint32_t sign_counter{};

		std::optional<AttestedCredentialData> attested_credential_data{};

		static AuthenticatorData fromBin(const std::vector<std::byte>& data);
		std::vector<std::byte> toBin();
	};
}

