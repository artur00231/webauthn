#include "WebAuthn.h"

std::optional<webauthn::MakeCredentialResult> webauthn::WebAuthn::makeCredential(const UserData& user)
{
    auto data = impl.makeCredential(user, rp);

    return data;
}

std::optional<webauthn::GetAssertionResult> webauthn::WebAuthn::getAssertion(const CredentialId& credential_id)
{
    auto data = impl.getAssertion(credential_id, rp);

    return data;
}

