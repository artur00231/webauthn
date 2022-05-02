#include "pch.h"

#include <EdDSAKey.h>
#include <Base64.h>
#include <Hash.h>

#include <OpenSSLErros.h>

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		//D6C4348446AAF17CC08C0F0EDEC30B6A23855F11C010FF737390BB39680AA21E;
		static std::vector<std::uint8_t> x_1 = { 0xD6, 0xC4, 0x34, 0x84, 0x46, 0xAA, 0xF1, 0x7C, 0xC0, 0x8C,
			0x0F, 0x0E, 0xDE, 0xC3, 0x0B, 0x6A, 0x23, 0x85, 0x5F, 0x11,
			0xC0, 0x10, 0xFF, 0x73, 0x73, 0x90, 0xBB, 0x39, 0x68, 0x0A,
			0xA2, 0x1E };

		//e8e8a03067e43a255faff34586d87ae7fd7cb758710ba540f354b0e4f53678920100000003 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
		static auto data_1 = "6OigMGfkOiVfr/NFhth65/18t1hxC6VA81Sw5PU2eJIBAAAAA2Zoeq34Yr13bI/Bi46fjiAIlxSFbuIzs5AqWR0NXykl"s;
		static auto signature_1 = "YozSpbYbP5JCQxqwIfV1gXsAnfIE97VHb3TXBdaxkhN2bk+lGpPosHX18ZFuHav3/W2tFZZgZ9llZMaMrF1rCg=="s;


		//078A954BAD7784C56D120050E373051380748F2FB34148BFBD705A309C1ECC9C;
		static std::vector<std::uint8_t> x_2 = { 0x07, 0x8A, 0x95, 0x4B, 0xAD, 0x77, 0x84, 0xC5, 0x6D, 0x12,
			0x00, 0x50, 0xE3, 0x73, 0x05, 0x13, 0x80, 0x74, 0x8F, 0x2F,
			0xB3, 0x41, 0x48, 0xBF, 0xBD, 0x70, 0x5A, 0x30, 0x9C, 0x1E,
			0xCC, 0x9C };

		static auto data_2 = "qwertyuiopasdfghjklzxcvbnm\n"s;
		static auto signature_2 = "7X/ejhTuYAZhFRJxbdX9mM6WDqzpNzLndI375VkuWCyRXLhPs0BB7NjEspC7watot8Oyb0btFXaX5OU5G6P4Cg=="s;

		static std::vector<std::uint8_t> x_3 = { 0x7f, 0x73, 0x80, 0xb9, 0xd8, 0x26, 0x37, 0x61, 0x0b, 0xca,
			0x09, 0x28, 0x36, 0x93, 0x67, 0x2c, 0x45, 0x1f, 0x7a, 0x9b,
			0x5c, 0xe5, 0xfc, 0x8e, 0x22, 0xcd, 0xe1, 0x26, 0x48, 0x64,
			0x42, 0x26, 0xfd, 0x28, 0xf0, 0x2a, 0x26, 0xec, 0x07, 0x14,
			0x5a, 0xec, 0x21, 0x49, 0x28, 0x29, 0xd5, 0xa1, 0x9d, 0x0d,
			0xcf, 0x34, 0xff, 0x14, 0x0d, 0x80, 0x80};

		static auto data_3 = "dyhasgduygwdhudhuiowahduwahdowahduhwaidughwudhouwaidhuiafiuahfueghirhfioehf7983yrf83yhf79fhub86y4gc8\n"s;
		static auto signature_3 = "WPwieVz83fzujRxxrPgC8WWoKSaET4IsihDFr+Oao7ZJtNEPLiczEFkBVzqhpH7amE7mAujms6MA5WTQ1snafhXzbj/lFFI3kNfBj7kUxjQLKNTYITeU5AwCS96JY7VXGwrsb7XRMyGIaFk241urkSsA"s;
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

		auto success = key->verify(*data_decoded, *signature_decoded);

		if (!success)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(EdDSAKeyTests, EdDSAKeyEd22519)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_2, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::signature_2);

		ASSERT_TRUE(signature_decoded);

		std::vector<std::byte> x{};
		std::transform(helpers::x_2.begin(), helpers::x_2.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = EdDSAKey::create(x, crypto::COSE::EdDSA_EC::Ed25519);
		ASSERT_TRUE(key);

		auto success = key->verify(data, *signature_decoded);

		if (!success)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(EdDSAKeyTests, EdDSAKeyEd448)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_3, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto signature_decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::signature_3);

		ASSERT_TRUE(signature_decoded);

		std::vector<std::byte> x{};
		std::transform(helpers::x_3.begin(), helpers::x_3.end(), std::back_inserter(x),
			[](auto x) { return static_cast<std::byte>(x); });

		auto key = EdDSAKey::create(x, crypto::COSE::EdDSA_EC::Ed448);
		ASSERT_TRUE(key);

		auto success = key->verify(data, *signature_decoded);

		if (!success)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}
}