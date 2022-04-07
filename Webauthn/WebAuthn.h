#pragma once

#include <optional>

#include "WebAuthnDef.h"
#include "WebAuthnImpl.h"
#include "AttestationObject.h"
#include "CredentialId.h"

namespace webauthn
{
	class WebAuthn
	{
	public:
		WebAuthn(const RelyingParty rp, impl::WebAuthnImpl& impl) : rp{ rp }, impl{ impl } {}

		std::optional<MakeCredentialResult> makeCredential(const UserData& user);
		std::optional<GetAssertionResult> getAssertion(const CredentialId& credential_id);

	private:
		const RelyingParty rp;
		impl::WebAuthnImpl& impl;
	};
}

