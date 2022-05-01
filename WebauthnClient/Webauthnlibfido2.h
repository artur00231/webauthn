#pragma once

#include "WebAuthnImpl.h"

#include "Libfido2Token.h"
#include "Libfido2Authenticator.h"

#include <vector>
#include <string>
#include <ranges>
#include <iterator>

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
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

		std::optional<GetAssertionResult> getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

		inline static constexpr std::size_t max_num_of_authenticators{ 64 };

	protected:
		std::optional<std::vector<Libfido2Authenticator>> getAvaiableFidoDevices();
		std::optional<Libfido2Authenticator> getUserSelectedDevice(const std::vector<Libfido2Authenticator>& authenticators);
		std::optional<Libfido2Authenticator> getSuitableDevice(const WebAuthnOptions& options);
		std::optional<Libfido2Authenticator> getSuitableDeviceForAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp, WebAuthnOptions options);
		std::vector<Libfido2Authenticator> filterAuthenticators(std::vector<Libfido2Authenticator> authenticators, const WebAuthnOptions& options);

	private:
		//Error message that can be showed to end user
		std::optional<std::string> user_error_msg{};

		//Wait time for "getUserSelectedDevice" function
		inline static constexpr std::size_t max_wait_time = 25; //s
		inline static constexpr int operation_timeout = 25; //s
		inline static constexpr std::size_t wait_time_device = 50; //ms

		//User will be asked to select authenticator, even if there is just one good authenticator
		inline static constexpr bool force_always_user_select{ false };
		//Allow automatic authenticator selection for getAssertion
		inline static constexpr bool auto_authenticator_get_assert{ true };

		const static std::string no_fido2_devices_err;
		const static std::string no_good_fido2_devices_err;
		const static std::string invalid_pin_err;
		const static std::string no_pin_err;
	};
}