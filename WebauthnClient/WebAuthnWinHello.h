#pragma once

#ifdef _WIN32

#include "WebAuthnImpl.h"

#include <Windows.h>
#include "../windows_webauthn/webauthn/webauthn.h"

#include <memory>

namespace webauthn::impl
{
	class WebAuthnWinHello : public WebAuthnImpl
	{
	public:
		using WebAuthNGetApiVersionNumber_t = decltype(&WebAuthNGetApiVersionNumber);
		using WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable_t = decltype(&WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable);
		using WebAuthNAuthenticatorMakeCredential_t = decltype(&WebAuthNAuthenticatorMakeCredential);
		using WebAuthNAuthenticatorGetAssertion_t = decltype(&WebAuthNAuthenticatorGetAssertion);
		using WebAuthNGetErrorName_t = decltype(&WebAuthNGetErrorName);
		using WebAuthNFreeAssertion_t = decltype(&WebAuthNFreeAssertion);
		using WebAuthNFreeCredentialAttestation_t = decltype(&WebAuthNFreeCredentialAttestation);

		class WebAuthnWinHelloDll
		{
		public:
			WebAuthnWinHelloDll();
			~WebAuthnWinHelloDll();

			WebAuthNGetApiVersionNumber_t WebAuthNGetApiVersionNumber{ nullptr };
			WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable_t WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable{ nullptr };
			WebAuthNAuthenticatorMakeCredential_t WebAuthNAuthenticatorMakeCredential{ nullptr };
			WebAuthNAuthenticatorGetAssertion_t WebAuthNAuthenticatorGetAssertion{ nullptr };
			WebAuthNGetErrorName_t WebAuthNGetErrorName{ nullptr };
			WebAuthNFreeAssertion_t WebAuthNFreeAssertion{ nullptr };
			WebAuthNFreeCredentialAttestation_t WebAuthNFreeCredentialAttestation{ nullptr };

			bool good() const noexcept { return isAvaiable; }
			operator bool() const noexcept { return isAvaiable; }

		private:
			HMODULE webauthn_lib{ nullptr };
			bool isAvaiable{};
		};

		WebAuthnWinHello();
		virtual ~WebAuthnWinHello();

		std::optional<MakeCredentialResult> makeCredential(const UserData& user, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

		std::optional<GetAssertionResult> getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) override;

	private:
		WebAuthnWinHelloDll webAuthnWinHelloDll{};
	};
}

#endif // _WIN32
