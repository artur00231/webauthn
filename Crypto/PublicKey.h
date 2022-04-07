#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstddef>
#include <memory>

#include "COSE.h"
#include "../CBOR/CBOR.h"

namespace webauthn::crypto
{
	class PublicKey
	{
	public:
		virtual std::optional<bool> verify(const std::string& data, const std::string& signature, const COSE::SIGNATURE_HASH hash) const = 0;
		virtual std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const COSE::SIGNATURE_HASH hash) const = 0;
	};

	std::optional<std::unique_ptr<PublicKey>> createPublicKey(const std::vector<std::byte>& cbor);
	std::optional<std::unique_ptr<PublicKey>> createPublicKey(CBOR::CBORHandle handle);
}
