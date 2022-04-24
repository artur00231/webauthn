#pragma once

#include "WebAuthnImpl.h"

#include <vector>
#include <string>
#include <ranges>
#include <iterator>

#include <format>

namespace webauthn::impl
{
	class Libfido2Authenticator;

	class Webauthnlibfido2 : public WebAuthnImpl
	{
	public:
		Webauthnlibfido2() = default;
		Webauthnlibfido2(const Webauthnlibfido2&) = default;
		Webauthnlibfido2& operator=(const Webauthnlibfido2&) = default;
		Webauthnlibfido2(Webauthnlibfido2&&) = default;
		Webauthnlibfido2& operator=(Webauthnlibfido2&&) = default;
		virtual ~Webauthnlibfido2() = default;

		std::optional<MakeCredentialResult> makeCredential(const UserData& user, const RelyingParty& rp,
			const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

		std::optional<GetAssertionResult> getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

		inline static constexpr std::size_t max_num_of_authenticators{ 64 };

	protected:
		std::optional<std::vector<Libfido2Authenticator>> getAvaiableFidoDevices();
		std::optional<Libfido2Authenticator> getUserSelectedDevice(const std::vector<Libfido2Authenticator>& authenticators);
		std::optional<Libfido2Authenticator> getSuitableDevice(const WebAuthnOptions& options);

		std::optional<MakeCredentialResult> makeCredential(const Libfido2Authenticator& authenticator, const UserData& user, const RelyingParty& rp,
			const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options);
		std::optional<GetAssertionResult> getAssertion(const Libfido2Authenticator& authenticator, const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options);

	private:
		//Error message that can be showed to end user
		std::optional<std::string> user_error_msg{};

		//Wait time for "getUserSelectedDevice" function
		inline static constexpr std::size_t max_wait_time = 25; //s
		inline static constexpr int operation_timeout = 25; //s
		inline static constexpr std::size_t wait_time_device = 50; //ms

		//User will be asked to select authenticator, even if there is just one good authenticator
		inline static constexpr bool force_always_user_select{ false };

		const static std::string no_fido2_devices_err;
		const static std::string no_good_fido2_devices_err;
		const static std::string invalid_pin_err;
		const static std::string no_pin_err;
	};

	class Libfido2Token
	{
		Libfido2Token() = default;

		friend Webauthnlibfido2;
	};

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

		//Returns empty optional if something went wrong, or authenticator wasn't fido2 compatible
		static std::optional<Libfido2Authenticator> createLibfido2Authenticator(std::string path, Libfido2Token token);

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