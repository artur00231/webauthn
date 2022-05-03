#include "pch.h"

#include <ECDSAKey.h>
#include <Base64.h>

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

		static std::vector<std::uint8_t> x_2 = { 0x88, 0x97, 0x70, 0x0c, 0xde, 0x58, 0x4f, 0xff, 0xd3, 0x2e, 
			0x68, 0x85, 0xea, 0x94, 0x3e, 0x40, 0x4d, 0x0d, 0x3c, 0x9d,
			0x44, 0xce, 0x2c, 0xaf, 0x06, 0x94, 0xa2, 0x1b, 0x8c, 0xe6,
			0x3c, 0xf6 };
		static std::vector<std::uint8_t> y_2 = { 0xaf, 0x71, 0x64, 0x49, 0x46, 0xfc, 0x2a, 0x45, 0xcc, 0x34,
			0x50, 0xcc, 0x83, 0x9e, 0xa8, 0x13, 0x52, 0x2a, 0xea, 0x5b,
			0xdb, 0x5e, 0xca, 0x2b, 0xb9, 0x42, 0xc9, 0xc6, 0x2f, 0x65,
			0x2e, 0x37 };

		static std::string data_2{ "qwertyuiopasdfghjklzxcvbnm\n" };
		static auto signature_2_sha256 = "MEQCIBgGexilSENcn7Op4WvmvBtPwv9Xzc/+wIHnWJq8WwpzAiBpQIek+0PIGJQ3IFHe++XpLqL5MCQfwZTmUL5CAGWNZQ=="s;
		static auto signature_2_sha384 = "MEYCIQCz7p6PT/O+XZu5Xq+IOTkj0aK5mJnLmaYlm26iHn8zqQIhALmRlvV2hWSW7LGT4z5EG9KH1ipnYnoc7oNXVf/YGNUA"s;
		static auto signature_2_sha512 = "MEUCIQDWZ+F/yf3UDSe3fHzk/tCEa5e9fW7/HlFP3VjvMlgajwIgVf0R9K0YMR6GMTFaQwVLl+x0vrYbAGAdR3RPfJE5koo="s;

		static std::vector<std::uint8_t> x_3 = { 0x00, 0x7d, 0x44, 0x03, 0x1c, 0xec, 0xef, 0xed, 0x35, 0x39,
			0x2a, 0xbc, 0xb2, 0x49, 0xa9, 0x6c, 0xa7, 0xb7, 0x03, 0x02,
			0x97, 0x89, 0x7b, 0x52, 0x0d, 0x1d, 0xc1, 0x8a, 0x53, 0xa7,
			0x6e, 0x26, 0xe1, 0x75, 0x43, 0xfc, 0x82, 0x17, 0x8b, 0xff,
			0x3f, 0x10, 0xe9, 0xbb, 0x28, 0x8d, 0x8e, 0x70, 0xe8, 0x03,
			0xfa, 0x3f, 0x2e, 0xa7, 0x02, 0x8f, 0x5f, 0xdb, 0x7d, 0x21,
			0x85, 0xc5, 0x5b, 0xaa, 0xd1, 0xf6 };
		static std::vector<std::uint8_t> y_3 = { 0x00, 0x3f, 0x18, 0x7d, 0x02, 0x7c, 0x0f, 0x4c, 0x8c, 0x2a,
			0x0f, 0xde, 0x44, 0xf9, 0x0b, 0x36, 0xa7, 0x12, 0x5e, 0xbc, 
			0x76, 0x6d, 0x25, 0x9a, 0x82, 0x79, 0x83, 0x65, 0xb1, 0x83, 
			0xea, 0x00, 0xa6, 0x56, 0x6f, 0x04, 0x0a, 0xb1, 0x16, 0xd7, 
			0xf9, 0x51, 0xd1, 0x3d, 0x8e, 0x31, 0xf2, 0x78, 0xf1, 0xea, 
			0xc1, 0x2d, 0x55, 0xf4, 0xd7, 0x1e, 0x3d, 0xac, 0x28, 0x47, 
			0xe5, 0x1a, 0xc5, 0x7e, 0x78, 0x25 };

		static std::string data_3{ "dsnfbhuycvuehrfeghf8oywrcgochrcowgrtv8y0rgyphfiuehfnviuhauhtvyogauchwnutnvoaiuhtcihgipuoahgciuoehgcpiuhagiuvlha\n" };
		static auto signature_3_sha256 = "MIGHAkIB1aTXiaTZVep+Vut//I4ApABaAI9nKh/ugz04pKhAtcjNKqlaN+NVqMi5+2XrJ+ESHvBOCV/0KHWp30/5qnHc6RYCQRImpvXMK9fzMdK8Au1bewSaap9bfvg/A08yBFVP0etnLJ2wwzO1QPSAsxMCLEsSYDKqcmQ6MU9R/+LKqWvqg38f"s;
		static auto signature_3_sha384 = "MIGIAkIAkqgNJ1MiUE9hHSowieKIuNxsq9U2TZs+HgbXdt7BdAharfltOS0dvAVyikZRwTlgSBHU8VxdoHLzXaHtsAzhtKwCQgDzzuDdMlPzo0dOBOyTN0fgOcmg9o8apXD6wxj2BLnIkcNlpyO3AiszyhcjQ2DwK89xcgOoeUeCI+0bf/Xsg37WLw=="s;
		static auto signature_3_sha512 = "MIGHAkIBsswx+uv9kIe9C8J2KUxejbHqg5t7NWW+FVulfJV+ba1tI/WmSJj65D/r+v5WRyCaZ/TMo5XaQeWE2QfyInrmqMACQSXmRhHxNA+RW4gqEPnFo4n/Osb6+lCC5JoNRKEyhYEam9ZmvPszL/JM0TPInQR4+dLNdgLQ+d1Uv+3EeQsyjwK/"s;

		static std::vector<std::uint8_t> x_4 = { 0x57, 0x8d, 0x8e, 0xf8, 0xbe, 0x21, 0x72, 0xf8, 0xa8, 0x55,
			0xc4, 0xb7, 0xe5, 0x70, 0x5d, 0x7c, 0xdc, 0xe5, 0xde, 0x79,
			0xa9, 0xd8, 0x10, 0xb2, 0x2f, 0x8e, 0x1d, 0x0e, 0x72, 0xe0,
			0xc4, 0x76, 0x28, 0x28, 0x0e, 0x8f, 0xfa, 0x6d, 0xba, 0x5f,
			0xd5, 0x9d, 0x20, 0x79, 0xab, 0xa3, 0xdf, 0x76 };
		static std::vector<std::uint8_t> y_4 = { 0x92, 0xcb, 0x2b, 0x68, 0xc4, 0xef, 0x9e, 0x0e, 0x96, 0x01, 
			0x99, 0x17, 0x6b, 0x1d, 0x90, 0x94, 0x1c, 0x66, 0x2d, 0xa6, 
			0x83, 0xaa, 0x7b, 0xa6, 0x0f, 0x15, 0x3b, 0x34, 0xf4, 0xe5, 
			0x1d, 0x0f, 0xd5, 0x55, 0x6b, 0x83, 0x79, 0x11, 0x35, 0x59, 
			0xa6, 0xeb, 0x4e, 0xc6, 0x7b, 0xab, 0x61, 0x58 };

		static std::string data_4{ "bfweiytgrygruicyruwg3ergoghrciyhaiou3ryhuiayvruywuriysuioryfuiwaryuivyruioweayruiynvhuihewnvrpypavyru\n" };
		static auto signature_4_sha256 = "MGYCMQDJQNQF/jFVIfHzg/PVFcZwNVJ92B9tt+5WZPh1PYgBGunKCA4t553oqDBZV2/mhk4CMQC/OcFJHsp+cEQN7+em1Xu4QZ1YnXzhvIQXc6oLMjDeDKZgY6l+8D21wBa6YcjLGUc="s;
		static auto signature_4_sha384 = "MGUCMQCP7GWBOT32RGjolMjQuw/794tFAP2MnJGcufox6NUKQuiFSYXA0FF/I8NNwseJYEwCMCnuFlghJAhiMfFRA20vyuV2oumxHwLJ8FUlsxfhHh1c3iS1etj6yK3jD/18QwWrAg=="s;
		static auto signature_4_sha512 = "MGYCMQDQuLzKhTM278Q6+dS+fWOjbqTwGC3hCMAaQQTE9na30kPOCXuNFbgJSdIN+nPDJJACMQDibqTXpRY5MTLIXUjB6l2eW9Txqal12qMCFrTx5d9G+yjQ078bSc3gRSHWCDQbST4="s;

		static std::vector<std::uint8_t> x_5 = { 0x0d, 0x66, 0xae, 0x49, 0x46, 0xa5, 0xe3, 0x69, 0x19, 0x65, 
			0x6b, 0xc7, 0x88, 0x04, 0x57, 0x81, 0x26, 0x8c, 0xae, 0xb7, 
			0xcf, 0xe9, 0xfc, 0x8d, 0xc9, 0xca, 0x30, 0x3c, 0xb4, 0x02, 
			0x70, 0xbc };
		static std::vector<std::uint8_t> y_5 = { 0x0f, 0x5b, 0x6a, 0x41, 0x84, 0x68, 0x28, 0x18, 0x36, 0x22, 
			0x47, 0x13, 0xc3, 0xc8, 0x67, 0x58, 0xb6, 0xc1, 0x56, 0x51, 
			0xdf, 0xb2, 0x3d, 0x95, 0x9a, 0xbd, 0x70, 0x22, 0x8f, 0xd8, 
			0xbb, 0x16 };

		static std::string data_5{ "yfggawejrhty98o3wury7cy4nv8by9482093802u54nv87b34wtrb98q3yc54b86b4c28qbny5r8736y4rc893n4r3wrb97v3y87r6y3vb9827935yv9b738yn5c9765v97836y5bvb8937y\n" };
		static auto signature_5_sha256 = "MEUCIQCfwUdyy4bk2BFCj0Zk1V8kLc3/xwgalayfiE3r/qgHiAIgMEaN1pyxvwmowQfp8AoDLZLZ72JiZqp15O7mVNDV0+A="s;
		static auto signature_5_sha384 = "MEYCIQCMXaSIusOHKPG8TXeFGeXwqTVcH8dANgc2MGVGVUN3dQIhAN/aa2teZcfowXfFhXAZDBTF3iYqymvp5uw3cnddIO+P"s;
		static auto signature_5_sha512 = "MEUCIA1vZIQMmCSiW+x1D6HCRcHpD2oTVRky72ZmeDE1+PHJAiEAv4LMtr5Km2hmKYaW3DYKL9Z8L1n5m+Yf6CGqOHpMp+A="s;

		//TODO ADD sha1 test!
	}

	TEST(ECDSAKeyTests, ECDSAKeyP256)
	{
		auto data_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::data_1);
		auto signature_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_1);

		ASSERT_TRUE(data_decoded);
		ASSERT_TRUE(signature_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_1.begin(), helpers::x_1.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_1.begin(), helpers::y_1.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::P256);
		ASSERT_TRUE(key);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		auto success = key->verify(*data_decoded, *signature_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(ECDSAKeyTests, ECDSAKeySHAP256)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_2, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_256_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_2_sha256);
		auto signature_384_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_2_sha384);
		auto signature_512_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_2_sha512);

		ASSERT_TRUE(signature_256_decoded);
		ASSERT_TRUE(signature_384_decoded);
		ASSERT_TRUE(signature_512_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_2.begin(), helpers::x_2.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_2.begin(), helpers::y_2.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::P256);
		ASSERT_TRUE(key);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		auto success = key->verify(data, *signature_256_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		success = key->verify(data, *signature_384_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		success = key->verify(data, *signature_512_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(ECDSAKeyTests, ECDSAKeySHAP521)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_3, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_256_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_3_sha256);
		auto signature_384_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_3_sha384);
		auto signature_512_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_3_sha512);

		ASSERT_TRUE(signature_256_decoded);
		ASSERT_TRUE(signature_384_decoded);
		ASSERT_TRUE(signature_512_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_3.begin(), helpers::x_3.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_3.begin(), helpers::y_3.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::P521);
		ASSERT_TRUE(key);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		auto success = key->verify(data, *signature_256_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		success = key->verify(data, *signature_384_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		success = key->verify(data, *signature_512_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(ECDSAKeyTests, ECDSAKeySHAPP384)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_4, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_256_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_4_sha256);
		auto signature_384_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_4_sha384);
		auto signature_512_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_4_sha512);

		ASSERT_TRUE(signature_256_decoded);
		ASSERT_TRUE(signature_384_decoded);
		ASSERT_TRUE(signature_512_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_4.begin(), helpers::x_4.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_4.begin(), helpers::y_4.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::P384);
		ASSERT_TRUE(key);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		auto success = key->verify(data, *signature_256_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		success = key->verify(data, *signature_384_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		success = key->verify(data, *signature_512_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(ECDSAKeyTests, ECDSAKeySHAsecp256k1)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_5, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_256_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_5_sha256);
		auto signature_384_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_5_sha384);
		auto signature_512_decoded = crypto::base64::fromBase64Url<std::vector<std::byte>>(helpers::signature_5_sha512);

		ASSERT_TRUE(signature_256_decoded);
		ASSERT_TRUE(signature_384_decoded);
		ASSERT_TRUE(signature_512_decoded);

		std::vector<std::byte> x{}, y{};
		std::transform(helpers::x_5.begin(), helpers::x_5.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });
		std::transform(helpers::y_5.begin(), helpers::y_5.end(), std::back_inserter(y),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = ECDSAKey::create(x, y, crypto::COSE::ECDSA_EC::secp256k1);
		ASSERT_TRUE(key);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		auto success = key->verify(data, *signature_256_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		success = key->verify(data, *signature_384_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);

		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		success = key->verify(data, *signature_512_decoded);
		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}
}