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

		std::optional<MakeCredentialResult> makeCredential(const UserData& user, const std::vector<std::byte>& challange,
			const std::optional<std::string>& password = {});

		//For server-side credentials credential_id.size != 0
		//For discoverable credentials credential_id.size == 0
		std::optional<GetAssertionResult> getAssertion(const std::vector<CredentialId>& credential_id, const std::vector<std::byte>& challange,
			const std::optional<std::string>& password = {});


		//If true, password must be provided as argument, if needed
		bool requirePassword() const noexcept;
	private:
		const RelyingParty rp;
		impl::WebAuthnImpl& impl;

		//Settings
		WebAuthnOptions options{};
	};
}

