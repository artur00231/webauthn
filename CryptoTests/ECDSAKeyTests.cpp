#include "pch.h"

#include "../Crypto/ECDSAKey.h"
#include "../Crypto/Base64.h"

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		//"C7B0FAB51347CCEC0FA2A492B513758AC493B0D7C682F9D2FD0C3017FA2C82A9"s;
		static std::vector<std::uint8_t> x_1 = { 0xC7, 0xB0, 0xFA, 0xB5, 0x13, 0x47, 0xCC, 0xEC, 0x0F, 0xA2, 
			0xA4, 0x92, 0xB5, 0x13, 0x75, 0x8A, 0xC4, 0x93, 0xB0, 0xD7, 
			0xC6, 0x82, 0xF9, 0xD2, 0xFD, 0x0C, 0x30, 0x17, 0xFA, 0x2C, 
			0x82, 0xA9 };

		//"A4439C63B5934507AC33F8CDB46392C418F3778B8C225DDEAC817A3DB593F616"s;
		static std::vector<std::uint8_t> y_1 = { 0xA4, 0x43, 0x9C, 0x63, 0xB5, 0x93, 0x45, 0x07, 0xAC, 0x33, 
			0xF8, 0xCD, 0xB4, 0x63, 0x92, 0xC4, 0x18, 0xF3, 0x77, 0x8B, 
			0x8C, 0x22, 0x5D, 0xDE, 0xAC, 0x81, 0x7A, 0x3D, 0xB5, 0x93, 
			0xF6, 0x16 };

		//E8E8A03067E43A255FAFF34586D87AE7FD7CB758710BA540F354B0E4F5367892010000001C 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
		static auto data_1 = "6OigMGfkOiVfr/NFhth65/18t1hxC6VA81Sw5PU2eJIBAAAAHGZoeq34Yr13bI/Bi46fjiAIlxSFbuIzs5AqWR0NXykl"s;
		static auto signature_1 = "MEUCIEwTxce0B4Ur90dZUNCTPEmexYKBAV8emcblBafUnDbbAiEA4J8fLlkF7E2cNbr++8/3fjIQQVEYp77wYwrstFoZMmA"s;
	}

	TEST(ECDSAKeyTests, ECDSAKeyCreate1)
	{
		auto data_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::data_1);
		auto signature_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::signature_1);

		ASSERT_TRUE(data_decoded);
		ASSERT_TRUE(signature_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_1.begin(), helpers::x_1.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_1.begin(), helpers::y_1.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::P256);
		ASSERT_TRUE(key);

		auto success = key->verify(*data_decoded, *signature_decoded, crypto::COSE::SIGNATURE_HASH::SHA256);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}
}