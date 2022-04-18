#pragma once

#include <vector>
#include <cstddef>
#include <string>
#include <optional>
#include <array>

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

	enum class EXTENSION : std::size_t { HMAC_SECRET = 0, CRED_PROTECT = 1 };
	static constexpr std::array<EXTENSION, 2> SupportedExtensions{ EXTENSION::HMAC_SECRET, EXTENSION::CRED_PROTECT };

	inline std::string getExtensionText(EXTENSION extension)
	{
		using namespace std::string_literals;

		switch (extension)
		{
		case webauthn::EXTENSION::HMAC_SECRET:
			return "hmac-secret"s;
		case webauthn::EXTENSION::CRED_PROTECT:
			return "credProtect"s;
		}

		return {};
	}

	//Not every option is supported
	enum class OPTION { PLATFORM/*is device attached to client*/, DISCOVERABLE/*can discoverable credentials be created*/, 
		CLIENT_PIN, UV/*user verification (buildin)*/, UP/*user presence*/ };
	static constexpr std::array<OPTION, 5> SupportedOptions{ OPTION::PLATFORM, OPTION::DISCOVERABLE, OPTION::CLIENT_PIN, OPTION::UV, OPTION::UP };

	inline std::string getOptionText(OPTION option)
	{
		using namespace std::string_literals;

		switch (option)
		{
		case webauthn::OPTION::PLATFORM:
			return "plat"s;
		case webauthn::OPTION::DISCOVERABLE:
			return "rk"s;
		case webauthn::OPTION::CLIENT_PIN:
			return "clientPin"s;
		case webauthn::OPTION::UV:
			return "uv"s;
		case webauthn::OPTION::UP:
			return "up"s;
		}

		return {};
	}

	struct WebAuthnOptions
	{
		//TODO add EdDSA
		std::vector<crypto::COSE::COSE_ALGORITHM> allowed_algorithms{ crypto::COSE::COSE_ALGORITHM::ES256 };

		USER_VERIFICATION user_verification{ USER_VERIFICATION::DISCOURAGED };
		ATTESTATION attestation{ ATTESTATION::NONE };
	};
}