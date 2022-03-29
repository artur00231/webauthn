#include "WebAuthn.h"

std::optional<webauthn::AttestationObject> webauthn::WebAuthn::makeCredentials(const UserData& user)
{
    auto data = impl.makeCredentials(user, rp);

    return {};
}

