#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstddef>

namespace webauthn::crypto
{
	enum class SIGNATURE_HASH { SHA256 = -16, SHA384 = -43, SHA512 = -44 };

	class PublicKey
	{
		virtual std::optional<bool> verify(const std::string& data, const std::string& signature, const SIGNATURE_HASH hash) const = 0;
		virtual std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const SIGNATURE_HASH hash) const = 0;
	};
}
