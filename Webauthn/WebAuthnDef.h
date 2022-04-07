#pragma once

#include <vector>
#include <cstddef>
#include <string>
#include <optional>

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

	struct MakeCredentialResult
	{
		std::vector<std::byte> attestation_object{};
	};


	struct GetAssertionResult
	{
		std::vector<std::byte> authenticator_data{};
		std::vector<std::byte> signature{};
		std::vector<std::byte> user_id{};
	};
}