#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstddef>
#include <memory>

#include "COSE.h"
#include <CBORLib.h>

#ifdef PUBLICKEY_CRYPTO_FORCE_FULL
#undef PUBLICKEY_CRYPTO_LITE
#endif // !PUBLICKEY_CRYPTO_FORCE_FULL

namespace webauthn::crypto
{
	class PublicKey
	{
	public:
		virtual ~PublicKey() = default;

		virtual std::optional<bool> verify(const std::string& data, const std::string& signature) const = 0;
		virtual std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature) const = 0;

#ifndef PUBLICKEY_CRYPTO_LITE
		static std::optional<std::unique_ptr<PublicKey>> createPublicKey(const std::vector<std::byte>& cbor);
		static std::optional<std::unique_ptr<PublicKey>> createPublicKey(CBOR::CBORHandle handle);
#endif // !PUBLICKEY_CRYPTO_LITE
	};
}
