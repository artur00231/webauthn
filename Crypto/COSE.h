#pragma once

#include <cstdint>
#include <array>

namespace webauthn::crypto
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

		enum class KEY_TYPE : std::int32_t { OKP = 1, EC = 2, RSA = 3 };

		enum class ECDSA_EC : std::int32_t { P256 = 1, P384 = 2, P521 = 3, secp256k1 = 8 };

		enum class EdDSA_EC : std::int32_t { Ed25519 = 6, Ed448 = 7 };

		enum class SIGNATURE_HASH : std::int32_t { SHA256 = -16, SHA384 = -43, SHA512 = -44 };

		inline constexpr bool isCOSE_ALGORITHM(std::int32_t value)
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

		inline constexpr bool isCOSE_ECDSA_EC(std::int32_t value)
		{
			constexpr std::array<ECDSA_EC, 4> enum_values = {
				ECDSA_EC::P256, ECDSA_EC::P384, ECDSA_EC::P521, ECDSA_EC::secp256k1 };

			for (auto&& enum_value : enum_values)
			{
				if (value == std::to_underlying(enum_value))
				{
					return true;
				}
			}

			return false;
		}

		inline constexpr bool isCOSE_EdDSA_EC(std::int32_t value)
		{
			constexpr std::array<EdDSA_EC, 2> enum_values = {
				EdDSA_EC::Ed25519, EdDSA_EC::Ed448 };

			for (auto&& enum_value : enum_values)
			{
				if (value == std::to_underlying(enum_value))
				{
					return true;
				}
			}

			return false;
		}

		inline constexpr bool isCOSE_KeyType(std::int32_t value)
		{
			constexpr std::array<KEY_TYPE, 3> enum_values = {
				KEY_TYPE::OKP, KEY_TYPE::EC, KEY_TYPE::RSA };

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