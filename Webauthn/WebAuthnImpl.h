#pragma once

#include "WebAuthnDef.h"
#include "CredentialId.h"

#include <optional>

namespace webauthn::impl
{
	class WebAuthnImpl
	{
	public:
		virtual ~WebAuthnImpl() = default;

		virtual std::optional<MakeCredentialResult> makeCredential(const UserData& user, const RelyingParty& rp) = 0;

		virtual std::optional<GetAssertionResult> getAssertion(const CredentialId& id, const RelyingParty& rp) = 0;
	};
}

