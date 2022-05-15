#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstddef>
#include <memory>

#include "COSE.h"
#include <CBORLib.h>

namespace webauthn::crypto
{
	class PublicKey
	{
	public:
		virtual ~PublicKey() = default;

		virtual std::optional<bool> verify(const std::string& data, const std::string& signature) const = 0;
		virtual std::optional<bool> verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature) const = 0;

		virtual bool good() const noexcept {
			return true;
		}
		operator bool() const noexcept {
			return good();
		}

		/*
		* If PUBLICKEY_CRYPTO_LITE is set, then createPublicKey will always return EmptyPublicKey
		*/
		static std::optional<std::unique_ptr<PublicKey>> createPublicKey(const std::vector<std::byte>& cbor);
		static std::optional<std::unique_ptr<PublicKey>> createPublicKey(CBOR::CBORHandle handle);
	};

	class EmptyPublicKey : public PublicKey
	{
		std::optional<bool> verify([[maybe_unused]] const std::string& data, [[maybe_unused]] const std::string& signature) const override {
			return {};
		}
		std::optional<bool> verify([[maybe_unused]] const std::vector<std::byte>& data, [[maybe_unused]] const std::vector<std::byte>& signature) const override {
			return {};
		}

		bool good() const noexcept override {
			return false;
		}
	};
}
