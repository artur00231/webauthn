#include "pch.h"

#include "../Crypto/EdDSAKey.h"
#include "../Crypto/Base64.h"

#include "../Crypto/OpenSSLErros.h"

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		//"A4439C63B5934507AC33F8CDB46392C418F3778B8C225DDEAC817A3DB593F616"s;
		static std::vector<std::uint8_t> x_1 = { 0xA4, 0x43, 0x9C, 0x63, 0xB5, 0x93, 0x45, 0x07, 0xAC, 0x33,
			0xF8, 0xCD, 0xB4, 0x63, 0x92, 0xC4, 0x18, 0xF3, 0x77, 0x8B,
			0x8C, 0x22, 0x5D, 0xDE, 0xAC, 0x81, 0x7A, 0x3D, 0xB5, 0x93,
			0xF6, 0x16 };

		//e8e8a03067e43a255faff34586d87ae7fd7cb758710ba540f354b0e4f53678920100000007 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
		static auto data_1 = "6OigMGfkOiVfr_NFhth65_18t1hxC6VA81Sw5PU2eJIBAAAAB2Zoeq34Yr13bI_Bi46fjiAIlxSFbuIzs5AqWR0NXykl"s;
		static auto signature_1 = "nQY-3owRntQ1YuLml2CamkY7U6C0dTB7j6TcB7dNUepkQZMJRI5ctVAWbiROcCdulBdcsZKIhHWZVGo-NYINCw"s;
	}

	TEST(EdDSAKeyTests, EdDSAKeyCreate1)
	{
		auto data_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::data_1);
		auto signature_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::signature_1);

		ASSERT_TRUE(data_decoded);
		ASSERT_TRUE(signature_decoded);

		std::vector<std::byte> x{};
		std::transform(helpers::x_1.begin(), helpers::x_1.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = EdDSAKey::create(x, crypto::COSE::EdDSA_EC::Ed25519);
		ASSERT_TRUE(key);

		auto success = key->verify(*data_decoded, *signature_decoded, crypto::COSE::SIGNATURE_HASH::SHA256);

		if (!success)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}
}