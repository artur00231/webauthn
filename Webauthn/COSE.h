#pragma once

#include <cstdint>
#include <array>

namespace webauthn
{
	namespace COSE
	{
		//Only subset of algorithms
		enum class COSE_ALGORITHM : std::int32_t
		{
			//RSA
			RS1 = -65535,
			RS256 = -259,
			RS384 = -258,
			RS512 = -257,

			//ECDSA
			ES256K = -47,
			ES512 = -36,
			ES384 = -35,
			ES256 = -7,

			//EdDSA
			EdDSA = -8
		};

		constexpr bool isCOSE_ALGORITHM(std::int32_t value)
		{
			constexpr std::array<COSE_ALGORITHM, 9> enum_values = {
				COSE_ALGORITHM::RS1, COSE_ALGORITHM::RS256, COSE_ALGORITHM::RS384, COSE_ALGORITHM::RS512,
				COSE_ALGORITHM::ES256K, COSE_ALGORITHM::ES512, COSE_ALGORITHM::ES384, COSE_ALGORITHM::ES256,
				COSE_ALGORITHM::EdDSA };

			for (auto&& enum_value : enum_values)
			{
				if (value == std::to_underlying(enum_value))
				{
					return true;
				}
			}

			return false;
		}
	}
}