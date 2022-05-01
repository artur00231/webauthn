#pragma once

#include "Libfido2Token.h"
#include <COSE.h>
#include <WebAuthnDef.h>

#include <ranges>

namespace webauthn::impl
{
	class Libfido2Authenticator
	{
	public:
		struct Supported
		{
			//Supports CTAP 2.1 Credential Management
			bool credman{};
			//Supports CTAP 2.1 Credential Protection
			bool cred_prot{};
			//Supports CTAP 2.1 UV token permissions
			bool permissions{};
			//Supports CTAP 2.0 Client PINs
			bool pin{};
			//Supports a built-in user verification method
			bool uv{};
		};

		struct MakeCredentialLibfido2Result
		{
			int success{};
			//Maybe empty
			std::string format{};
			//Maybe empty
			std::vector<std::byte> authenticator_data{};
			//Maybe empty
			std::vector<std::byte> attestation_statement{};
		};

		// n-th signature is coresponding 
		struct GetAssertionLibfido2Result
		{
			int success{};
			struct AssertData
			{
				std::vector<std::byte> user_id{};
				std::vector<std::byte> signature{};
				std::vector<std::byte> cbor_authdata{};
			};

			//Maybe empty
			std::vector<AssertData> assert_datas{};
		};

		//Returns empty optional if something went wrong, or authenticator wasn't fido2 compatible
		static std::optional<Libfido2Authenticator> createLibfido2Authenticator(std::string path, Libfido2Token token);

		MakeCredentialLibfido2Result makeCredential(Libfido2Token token, const UserData& user, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options);
		GetAssertionLibfido2Result getAssertion(Libfido2Token token, const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options);


		std::string getPath() const { return path; }
		Supported getSupported() const noexcept { return supported; };

		//Is windows hello
		bool winhello() const noexcept { return is_winhello; }

		//Has it set a CTAP 2.0 Client PIN
		bool hasPin() const noexcept { return has_pin; }

		//Has it convigured user verification feature
		bool hasUv() const noexcept { return has_pin; }

		bool supports(OPTION option) const noexcept;
		bool supports(EXTENSION extension) const noexcept;

		template<std::ranges::input_range Range>
			requires std::is_same_v<crypto::COSE::COSE_ALGORITHM, std::iter_value_t<Range>>
		inline bool chooseAlgoritm(Range&& range);

		auto getChosenAlgorithm() const noexcept { return chosen_algorithm; }

		//From most prefered to least prefered 
		inline constexpr static std::array<crypto::COSE::COSE_ALGORITHM, 3> supported_algorithms{ crypto::COSE::COSE_ALGORITHM::EdDSA, crypto::COSE::COSE_ALGORITHM::ES256, crypto::COSE::COSE_ALGORITHM::RS256 };

	private:
		Libfido2Authenticator() = default;

		std::string path{};

		bool is_winhello{};

		Supported supported{};
		bool has_pin{};
		bool has_uv{};

		//Supported COSE algorithms
		std::vector<crypto::COSE::COSE_ALGORITHM> algorithms{};

		std::optional<crypto::COSE::COSE_ALGORITHM> chosen_algorithm{};

		//Supported extensions
		std::vector<EXTENSION> extensions{};

		//Supported options
		std::vector<std::pair<OPTION, bool>> options{};

		//Return error, even if libfido2 library error is not critical
		static constexpr const bool aggresive_errors{ true };
	};

	template<std::ranges::input_range Range>
		requires std::is_same_v<crypto::COSE::COSE_ALGORITHM, std::iter_value_t<Range>>
	inline bool Libfido2Authenticator::chooseAlgoritm(Range&& range)
	{
		chosen_algorithm = {};

		for (auto algorithm : supported_algorithms | std::views::filter([this](auto x) { return std::ranges::find(this->algorithms, x) != this->algorithms.end(); }))
		{
			if (std::ranges::find(range, algorithm) != range.end())
			{
				chosen_algorithm = algorithm;
				return true;
			}
		}

		return false;
	}
}