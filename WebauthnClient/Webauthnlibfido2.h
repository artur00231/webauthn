#pragma once

#include "WebAuthnImpl.h"

#include <vector>
#include <string>

#include <format>

namespace webauthn::impl
{
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

		struct fido2_device_info
		{
			std::string path{};

			bool is_winhello{};

			//Supports CTAP 2.1 Credential Management
			bool supports_credman{};
			//Supports CTAP 2.1 Credential Protection
			bool supports_cred_prot{};
			//Supports CTAP 2.1 UV token permissions
			bool supports_permissions{};
			//Supports CTAP 2.0 Client PINs
			bool supports_pin{};
			//Supports a built-in user verification method
			bool supports_uv{};

			//Has it set a CTAP 2.0 Client PIN
			bool has_pin{};
			//Has it convigured user verification feature
			bool has_uv{};

			//Supported COSE algorithms
			std::vector<crypto::COSE::COSE_ALGORITHM> algorithms{};

			//Supported extensions
			std::vector<EXTENSION> extensions{};

			//Supported options
			std::vector<std::pair<OPTION, bool>> options{};
		};

		std::optional<std::vector<std::string>> getAvaiableFidoDevices();
		std::optional<fido2_device_info> getFido2DeviceInfo(const std::string& path);

		std::optional<std::string> getUserSelectedDevice(const std::vector<std::string>& paths);

	protected:
		void error(std::string error_message);

	private:
		//Library errors
		std::vector<std::string> errors{};

		//Error message that can be showed to end user
		std::optional<std::string> user_error_msg{};

		//Wait time for "getUserSelectedDevice" function
		inline static constexpr std::size_t max_wait_time = 25; //s
		inline static constexpr std::size_t wait_time_device = 50; //ms
	};
}