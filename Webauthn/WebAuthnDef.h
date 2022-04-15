#pragma once

#include <vector>
#include <cstddef>
#include <string>
#include <optional>

#include "../Crypto/COSE.h"

namespace webauthn
{
	struct RelyingParty
	{
		std::string ID{};
		std::string name{};
	};

	struct UserData
	{
		/**
		* Maximum 64 bytes
		* Cannot contain personal information
		* Should be diffrent for each accont
		*/
		std::vector<std::byte> ID{};
		std::string name{};
		std::string display_name{};

		static std::optional<std::vector<std::byte>> generateRandomID(std::size_t size);
	};

	class CredentialId
	{
	public:
		std::vector<std::byte> id{};
	};

	struct MakeCredentialResult
	{
		std::vector<std::byte> attestation_object{};
	};


	struct GetAssertionResult
	{
		std::vector<std::byte> authenticator_data{};
		std::vector<std::byte> signature{};

		//May not be present in non discoverable credentials
		std::optional<std::vector<std::byte>> user_id{};
	};

	enum class USER_VERIFICATION { REQUIRED, PREFERRED, DISCOURAGED };
	enum class ATTESTATION { NONE, INDIRECT, DIRECT };

	struct WebAuthnOptions
	{
		//TODO add EdDSA
		std::vector<crypto::COSE::COSE_ALGORITHM> allowed_algorithms{ crypto::COSE::COSE_ALGORITHM::ES256 };

		USER_VERIFICATION user_verification{ USER_VERIFICATION::DISCOURAGED };
		ATTESTATION attestation{ ATTESTATION::NONE };
	};
}