#pragma once

#include <vector>
#include <cstddef>

namespace webauthn
{
	class CredentialId
	{
	public:
		std::vector<std::byte> id{};
	};
}