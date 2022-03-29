#pragma once

#include <memory>
#include <vector>
#include <cstddef>
#include <optional>
#include <string_view>

namespace webauthn
{
	class Attestation
	{
	public:
		enum class Format { None };

		virtual bool canAttest() const = 0;
	};

	namespace AttestationFactory
	{
		std::optional<Attestation::Format> getFormat(std::string_view fmt);

		std::unique_ptr<Attestation> praseAttestation(const std::vector<::std::byte>& cbor);
	}
}

