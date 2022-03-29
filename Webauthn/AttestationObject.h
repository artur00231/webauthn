#pragma once

#include "AuthenticatorData.h"
#include "Attestation.h"

#include <string>

namespace webauthn
{
	class AttestationObject
	{
	public:
		Attestation::Format format{};
		AuthenticatorData authenticator_data{};

		static AttestationObject fromCbor(const std::vector<std::byte>& data);
		std::vector<std::byte> toCbor() const;

	private:

	};
}
