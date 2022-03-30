#include "pch.h"

#include "../Crypto/ECDSAKey.h"
#include "../Crypto/Base64.h"

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static auto x_1 = "C7B0FAB51347CCEC0FA2A492B513758AC493B0D7C682F9D2FD0C3017FA2C82A9"s;
		static auto y_1 = "A4439C63B5934507AC33F8CDB46392C418F3778B8C225DDEAC817A3DB593F616"s;

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

		auto key = ECDSAKey::create(helpers::x_1, helpers::y_1, crypto::ECDSA_EC::P256);
		ASSERT_TRUE(key);

		auto success = key->verify(*data_decoded, *signature_decoded, crypto::SIGNATURE_HASH::SHA256);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}
}