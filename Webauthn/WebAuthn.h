#pragma once

#include <optional>

#include "WebAuthnDef.h"
#include "WebAuthnImpl.h"
#include "AttestationObject.h"

namespace webauthn
{
	class WebAuthn
	{
	public:
		WebAuthn(const RelyingParty rp, impl::WebAuthnImpl& impl) : rp{ rp }, impl{ impl } {}

		std::optional<AttestationObject> makeCredentials(const UserData& user);

	private:
		const RelyingParty rp;
		impl::WebAuthnImpl& impl;
	};
}

