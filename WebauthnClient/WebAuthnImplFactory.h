#pragma once

#include "WebAuthnImpl.h"
#include <memory>
#include <optional>
#include <vector>

namespace webauthn
{
	class WebAuthnImplFactory
	{
	public:
		static std::unique_ptr<impl::WebAuthnImpl> createWebAuthnImpl(std::optional<std::string> implementation = { "internal"});
		
		static std::vector<std::string> getAvaiableImplementations();

		inline static constexpr auto environment_variable_name = "WEBAUTHN_SK_IMPLEMENTATION";
	};
}