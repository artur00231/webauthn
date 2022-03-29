#pragma once

#include "WebAuthnDef.h"

#include <optional>

namespace webauthn::impl
{
	class WebAuthnImpl
	{
	public:
		virtual std::optional<std::vector<std::byte>> makeCredentials(const UserData& user, const RelyingParty& rp) = 0;
	};
}

