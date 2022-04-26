#include "WebAuthn.h"

std::optional<webauthn::MakeCredentialResult> webauthn::WebAuthn::makeCredential(const UserData& user, const std::vector<std::byte>& challenge,
    const std::optional<std::string>& password)
{
    auto data = impl.makeCredential(user, rp, challenge, password, options);

    return data;
}

std::optional<webauthn::GetAssertionResult> webauthn::WebAuthn::getAssertion(const std::vector<CredentialId>& credential_id, const std::vector<std::byte>& challenge,
    const std::optional<std::string>& password)
{
    auto data = impl.getAssertion(credential_id, rp, challenge, password, options);

    return data;
}

bool webauthn::WebAuthn::requirePassword() const noexcept
{
    return false;
}

