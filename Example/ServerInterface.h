#pragma once

#include <string>
#include <vector>
#include <optional>

#include "../Webauthn/WebAuthnDef.h"
#include "../Webauthn/CredentialId.h"

class ServerInterface
{
public:
	enum class LOGIN_RESULT
	{
		SUCCESS, WRONG_DATA, AUTH_REQ
	};

	struct LoginResult
	{
		LOGIN_RESULT result{};
		std::optional<webauthn::CredentialId> credential_id{};
	};

	virtual bool userExists(const std::string& name) = 0;
	virtual bool createUser(const std::string& name, const std::string& passw) = 0;
	virtual LoginResult loginUser(const std::string& name, const std::string& passw) = 0;
	virtual bool performWebauthn(const webauthn::GetAssertionResult& result) = 0;

	virtual bool addWebauthn(const std::string& name, const webauthn::MakeCredentialResult& result, 
		const webauthn::RelyingParty& rp, const webauthn::UserData& user) = 0;
};