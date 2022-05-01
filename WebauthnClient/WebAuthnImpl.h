#pragma once

#include <WebAuthnDef.h>
#include <optional>

namespace webauthn::impl
{
	class WebAuthnImpl
	{
	public:
		virtual ~WebAuthnImpl() = default;

		virtual std::optional<MakeCredentialResult> makeCredential(const UserData& user, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) = 0;

		virtual std::optional<GetAssertionResult> getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp,
			const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options) = 0;
	};
}

