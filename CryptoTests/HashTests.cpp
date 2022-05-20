#include "pch.h"

#include <Hash.h>

#include <ranges>
#include <array>
#include <cstring>

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static std::string removeSpaces(std::string_view tex)
		{
			std::string new_text{};
			std::ranges::copy(tex | std::views::filter([](auto x) { return x != ' '; }), std::back_inserter(new_text));
			return new_text;
		}

		static std::vector<std::byte> hexToBin(std::string_view hex)
		{
			std::vector<std::byte> data{};
			auto fromHex = [](char x) -> std::uint8_t {
				if (x >= '0' && x <= '9')
					return (x - '0');
				if (x >= 'A' && x <= 'F')
					return (x - 'A' + 10);
				if (x >= 'a' && x <= 'f')
					return (x - 'a' + 10);

				throw std::runtime_error{ R"("fromHex" Invalid character)" };
			};

			for (std::size_t i = 0; i < hex.size(); i += 2)
			{
				std::uint8_t value = (fromHex(hex[i]) << 4) | fromHex(hex[i + 1]);
				data.push_back(static_cast<std::byte>(value));
			}

			return data;
		}

		template<typename T, typename U>
		static bool compare(const U& value, const std::vector<std::byte>& good_data)
		{
			if (!std::is_same_v<T, U>)
			{
				return false;
			}

			if constexpr (sizeof(typename T::value_type) != 1)
			{
				return false;
			}

			if constexpr (alignof(typename T::value_type) != alignof(std::byte))
			{
				return false;
			}

			if (value.size() != good_data.size())
			{
				return false;
			}

			return 0 == std::memcmp(reinterpret_cast<const void*>(value.data()), reinterpret_cast<const void*>(good_data.data()), good_data.size());
		}

		static auto text1 = "ifshdvfgiurytiophtohzlihguioaytv78eytuiveio"s;
		static std::vector<std::uint8_t> data1{ 0x69, 0x6F, 0x6D, 0x6E, 0x62, 0x75, 0x75, 0x6D, 0x38, 0x30, 0x77, 0x76, 0x68, 0x6E, 0x67, 0x75, 0x6F, 0x73, 0x65, 0x75, 0x6A, 0x6D, 0x38, 0x65, 0x34, 0x61, 0x30, 0x79, 0x6E, 0x74, 0x76, 0x38, 0x6F, 0x75, 0x61, 0x6A, 0x70, 0x74, 0x75, 0x39, 0x68, 0x76, 0x38, 0x37, 0x30, 0x73, 0x6D };
		static std::vector<std::byte> data2{ std::byte{ 0x00 }, std::byte{ 0xAB }, std::byte{ 0x84 }, std::byte{ 0xF0 }, std::byte{ 0xDD } };


		static auto text1_sha1 = hexToBin("c1d0d3a9fb9542dd837fe090ffc689289cd911ff");
		static auto text1_sha256 = hexToBin("0e867f666f7dd1d6b9946eaa145e656f55c486be2a73bdc598d8df02199e4bff");
		static auto text1_sha384 = hexToBin("cde05b5bf28e382a142c7aec08db3a6731055a7a408bff673028a5cddacc2f4b5769a62ba6ebc5cc4e4a7f0c6e9b1c59");
		static auto text1_sha512 = hexToBin("4c2b95a690b07c399f38967169e1e835b64ee18abc1469436108b1428ad4e96aad7ad056ef6feec7f1f0ae926b4b57731cc273eb1ddbdeb78fee2b5262f050a0");

		static auto data1_sha1 = hexToBin("15e2944e1e80c1f2f40f965bc31c22b379f5eae0");
		static auto data1_sha256 = hexToBin("f919f5929547e2cd8d7490a4986f267e942c660d661b64d7aec2233cbea70b53");
		static auto data1_sha384 = hexToBin("ed9c2f449f23a8756c768bfa93c63914312bfee9601438fbf9492c11714f3ac5a79b57ec6779374db02ab3c98855b9ac");
		static auto data1_sha512 = hexToBin("b3e01a88160596854bda9f835425fa76422e616241a7149815131c8096d344411d7c41a8f9c9fcfda943001fd8d6f91f7455e78f8080ae689e7d5e643d5a4bee");

		static auto data2_sha1 = hexToBin("845f465c90725bc4cbc24adb439816a335d3dcdb");
		static auto data2_sha256 = hexToBin("b12543d4baee2fa014fbaa4ff6cb0fed8e0cd869653eadddad3331aa6e17fae1");
		static auto data2_sha384 = hexToBin("2a43066c28e8dbe03141896678d14e0e0a85ff41026aada31edc6bf631dac1801ac16002c0d01c7344c5225dbc44f3e2");
		static auto data2_sha512 = hexToBin("0ca44d2950db999ad544858bdf2bbb696efb69a28b44c2575b94661eed54f9a2fba7cd1bbcfa337f44fce3207d8d4129efef2ce35978a43f398ec413ba7b1638");


		static auto pass1 = "qwerty!"s;
		static auto pass2 = std::vector<std::uint8_t>{ 0x6a, 0x68, 0x66, 0x75, 0x73, 0x65, 0x79, 0x6e, 0x5f, 0x69, 0x75, 0x73, 0x65, 0x66, 0x67, 0x66, 0x65, 0x73, 0x66 };
		static auto pass3 = std::vector<std::byte>{ std::byte{ 0x6d }, std::byte{ 0x61 }, std::byte{ 0x6e }, std::byte{ 0x66 }, std::byte{ 0x55 } };

		static auto salt1 = "asdfghjk"s;
		static auto salt2 = std::vector<std::uint8_t>{ 0xF0, 0x0F, 0x0B, 0x1D, 0x00, 0x8C, 0x42, 0x10 };
		static auto salt3 = std::vector<std::byte>{ std::byte{ 0x0A }, std::byte{ 0xAB }, std::byte{ 0x8C }, std::byte{ 0xFD }, std::byte{ 0xDE }, std::byte{ 0x7B }, std::byte{ 0x59 }, std::byte{ 0xDF } };

		static constexpr std::size_t num_of_rounds1 = 1000;
		static constexpr std::size_t num_of_rounds2 = 10000;
		static constexpr std::size_t num_of_rounds3 = 100;

		static auto PBKDF2_1 = hexToBin(removeSpaces("c0 52 77 cf 19 d9 14 57 da 14 55 7f 84 7d d1 a5 22 f1 44 ac 14 79 fe d5 3d fd 64 5c 65 84 15 2d 13 25 68 23 51 64 33 c0 1e 9e 19 06 d1 fd 03 3c 7e b6 31 75 d3 c3 6e 8b 0d 0f 9e a3 88 17 15 a4 14 81 3d f9 38 72 a1 99 5e 0a cd 93 78 d4 ca 23 3c 7b 81 d7 11 01 d2 54 0c 91 96 b4 57 6c 19 26 ab e1 5c 3d 99 c1 ac a1 ca 54 0d ab 22 66 d2 28 d6 60 64 40 c7 a6 d0 91 c6 33 70 f6 72 c8 71 26"));
		static auto PBKDF2_2 = hexToBin(removeSpaces("93 46 53 38 04 99 54 47 2f c9 c1 19 24 a4 aa 6f d1 39 3c fe bb 02 f5 a7 08 30 0a 9e b9 4e 51 53 36 14 1e ca 7c 98 db 09 fd 9e 29 2e f6 d4 67 8a 60 b1 51 a7 54 58 f7 ac d9 2f 5d d1 da 05 35 01 0f d0 b6 8d 9e 37 64 cf c5 94 12 5b 12 09 31 ef 9c ab 9d 61 e2 6c 17 3d f9 df fb a8 0b 1e c2 24 f2 9a d9 71 5b 07 37 55 6e 79 db c3 a4 51 81 df 35 06 c2 bf 81 ca a3 42 57 02 5f 61 45 d4 51 4d 86 dc 22 4a 2d 08 64 db 8d 64 5f 31 0b 20 73 42 fe 37 fc 47 68 90 63 ed 30 cc 62 b5 24 b2 95 95 70 f1 fe 84 38 91 1f 18 08 9b a4 f7 45 51 41 a6 37 d9 7e 1a 05 d9 7c eb 89 ea b3 a2 62 9e 74 42 4c 19 8e 25 04 e9 9c a8 eb 37 ef 64 2e 57 48 64 ef dd 20 7c 8d f5 88 bf bb eb 87 a3 ca ce 09 31 34 6d 35 27 cb ac 0a d3 14 3e fd d3 98 0c c5 93 61 79 7e b1 43 d2 8d 70 0c 64 a1 9c e7 c8 23 0c a1 7e d8 d2 ba f2 6a 5b 48 14 cf 69 07 ca 3e 9e 35 2f b7 24 89 7d a0 07 33 4e 1a 3d 83 55 42 67 e3 ce 42 5b 19 89 79 20 5e ff 5b 4a 51 75 0f 13 3e f0 5e d7 87 88 c8 62 fe c4 c1 14 6a 80 62 53 3b d7 3a 22 5a 76 19 18 43 f1 b1 df a9 46 24 cf 4e b2 f3 f1 30 c4 b3 48 a3 22 73 b6 0d e5 25 9f 3c f9 72 52 d3 ce 34 98 bd 04 9e 70 58 32 25 fa 9b ad 9d 26 e9 00 f2 d4 04 88 8c fc 79 22 bb b2 06 f4 13 a2 43 c1 d1 7e 7b ab 5f f4 dd 85 7a fa 26 56 04 56 c7 3b bf 09 3e 9a 93 93 63 f6 d1 1d 23 cd b4 0a c1 c3 7f 04 ee e5 82 09 2b a0 34 b0 1c 63 a5 8e 1b 46 e1 3b 74 4d 71 96 42 d7 48 30 e1 62 e1 64 e2 cc f3 1f 46 0b d6 c7 40 f0 52 7d 71 fe 0d ee f6 9f 83 a6 fb 2a 86 eb 0a 30 ea e8 28 ba a6 1a 93 42 6d 44 23 ad 42 95 54 8d 2f 78 1a 86 c1 ee c1 9f 1a db 0a d2 e2 ff 85 5a 63 7b"));
		static auto PBKDF2_3 = hexToBin(removeSpaces("67 bf 78 0e 88 7d 23 ac c5 9c b5 30 57 96 16 2e a0 5d 02 65 31 75 56 a4 cb ab d1 b6 33 2a 48 0b"));

	}

	TEST(HashTests, SHA1_1)
	{
		auto a_value = hash::SHA1(helpers::text1);
		auto vb_value = hash::SHA1<std::vector<std::byte>>(helpers::text1);
		auto vu_value = hash::SHA1<std::vector<std::uint8_t>>(helpers::text1);
		auto s_value = hash::SHA1<std::string>(helpers::text1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::text1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::text1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha1);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::data1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA1_2)
	{
		auto a_value = hash::SHA1(helpers::data1);
		auto vb_value = hash::SHA1<std::vector<std::byte>>(helpers::data1);
		auto vu_value = hash::SHA1<std::vector<std::uint8_t>>(helpers::data1);
		auto s_value = hash::SHA1<std::string>(helpers::data1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::data1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha1);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::text1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA1_3)
	{
		auto a_value = hash::SHA1(helpers::data2);
		auto vb_value = hash::SHA1<std::vector<std::byte>>(helpers::data2);
		auto vu_value = hash::SHA1<std::vector<std::uint8_t>>(helpers::data2);
		auto s_value = hash::SHA1<std::string>(helpers::data2);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::data2_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha1);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 20>>(a_value, helpers::text1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA256_1)
	{
		auto a_value = hash::SHA256(helpers::text1);
		auto vb_value = hash::SHA256<std::vector<std::byte>>(helpers::text1);
		auto vu_value = hash::SHA256<std::vector<std::uint8_t>>(helpers::text1);
		auto s_value = hash::SHA256<std::string>(helpers::text1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::text1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::text1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha256);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::data1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha384);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA256_2)
	{
		auto a_value = hash::SHA256(helpers::data1);
		auto vb_value = hash::SHA256<std::vector<std::byte>>(helpers::data1);
		auto vu_value = hash::SHA256<std::vector<std::uint8_t>>(helpers::data1);
		auto s_value = hash::SHA256<std::string>(helpers::data1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::data1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha256);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::text1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha384);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA256_3)
	{
		auto a_value = hash::SHA256(helpers::data2);
		auto vb_value = hash::SHA256<std::vector<std::byte>>(helpers::data2);
		auto vu_value = hash::SHA256<std::vector<std::uint8_t>>(helpers::data2);
		auto s_value = hash::SHA256<std::string>(helpers::data2);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::data2_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha256);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha256);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::text1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha1);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha384);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA384_1)
	{
		auto a_value = hash::SHA384(helpers::text1);
		auto vb_value = hash::SHA384<std::vector<std::byte>>(helpers::text1);
		auto vu_value = hash::SHA384<std::vector<std::uint8_t>>(helpers::text1);
		auto s_value = hash::SHA384<std::string>(helpers::text1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::text1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::text1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha384);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::data1_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA384_2)
	{
		auto a_value = hash::SHA384(helpers::data1);
		auto vb_value = hash::SHA384<std::vector<std::byte>>(helpers::data1);
		auto vu_value = hash::SHA384<std::vector<std::uint8_t>>(helpers::data1);
		auto s_value = hash::SHA384<std::string>(helpers::data1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::data1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha384);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::text1_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA384_3)
	{
		auto a_value = hash::SHA384(helpers::data2);
		auto vb_value = hash::SHA384<std::vector<std::byte>>(helpers::data2);
		auto vu_value = hash::SHA384<std::vector<std::uint8_t>>(helpers::data2);
		auto s_value = hash::SHA384<std::string>(helpers::data2);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::data2_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha384);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha384);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 48>>(a_value, helpers::text1_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha384);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha512);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA512_1)
	{
		auto a_value = hash::SHA512(helpers::text1);
		auto vb_value = hash::SHA512<std::vector<std::byte>>(helpers::text1);
		auto vu_value = hash::SHA512<std::vector<std::uint8_t>>(helpers::text1);
		auto s_value = hash::SHA512<std::string>(helpers::text1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::text1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::text1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha512);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::data1_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::text1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::text1_sha1);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA512_2)
	{
		auto a_value = hash::SHA512(helpers::data1);
		auto vb_value = hash::SHA512<std::vector<std::byte>>(helpers::data1);
		auto vu_value = hash::SHA512<std::vector<std::uint8_t>>(helpers::data1);
		auto s_value = hash::SHA512<std::string>(helpers::data1);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::data1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha512);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::text1_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data1_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data1_sha1);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, SHA512_3)
	{
		auto a_value = hash::SHA512(helpers::data2);
		auto vb_value = hash::SHA512<std::vector<std::byte>>(helpers::data2);
		auto vu_value = hash::SHA512<std::vector<std::uint8_t>>(helpers::data2);
		auto s_value = hash::SHA512<std::string>(helpers::data2);

		//GOOD
		auto result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::data2_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data2_sha512);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha512);
		EXPECT_TRUE(result);

		//BAD
		result = helpers::compare<std::array<std::byte, 64>>(a_value, helpers::text1_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::data2_sha256);
		EXPECT_FALSE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::data1_sha512);
		EXPECT_FALSE(result);

		result = helpers::compare<std::string>(s_value, helpers::data2_sha1);
		EXPECT_FALSE(result);
	}

	TEST(HashTests, PBKDF2_1)
	{
		auto a_value = hash::PBKDF2<128>(helpers::pass1, helpers::salt1, helpers::num_of_rounds1);
		auto vb_value = hash::PBKDF2<128, std::vector<std::byte>>(helpers::pass1, helpers::salt1, helpers::num_of_rounds1);
		auto vu_value = hash::PBKDF2<128, std::vector<std::uint8_t>>(helpers::pass1, helpers::salt1, helpers::num_of_rounds1);
		auto s_value = hash::PBKDF2<128, std::string>(helpers::pass1, helpers::salt1, helpers::num_of_rounds1);

		auto result = helpers::compare<std::array<std::byte, 128>>(a_value, helpers::PBKDF2_1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::PBKDF2_1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::PBKDF2_1);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::PBKDF2_1);
		EXPECT_TRUE(result);
	}

	TEST(HashTests, PBKDF2_2)
	{
		auto a_value = hash::PBKDF2<512>(helpers::pass2, helpers::salt2, helpers::num_of_rounds2);
		auto vb_value = hash::PBKDF2<512, std::vector<std::byte>>(helpers::pass2, helpers::salt2, helpers::num_of_rounds2);
		auto vu_value = hash::PBKDF2<512, std::vector<std::uint8_t>>(helpers::pass2, helpers::salt2, helpers::num_of_rounds2);
		auto s_value = hash::PBKDF2<512, std::string>(helpers::pass2, helpers::salt2, helpers::num_of_rounds2);

		auto result = helpers::compare<std::array<std::byte, 512>>(a_value, helpers::PBKDF2_2);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::PBKDF2_2);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::PBKDF2_2);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::PBKDF2_2);
		EXPECT_TRUE(result);
	}

	TEST(HashTests, PBKDF2_3)
	{
		auto a_value = hash::PBKDF2<32>(helpers::pass3, helpers::salt3, helpers::num_of_rounds3);
		auto vb_value = hash::PBKDF2<32, std::vector<std::byte>>(helpers::pass3, helpers::salt3, helpers::num_of_rounds3);
		auto vu_value = hash::PBKDF2<32, std::vector<std::uint8_t>>(helpers::pass3, helpers::salt3, helpers::num_of_rounds3);
		auto s_value = hash::PBKDF2<32, std::string>(helpers::pass3, helpers::salt3, helpers::num_of_rounds3);

		auto result = helpers::compare<std::array<std::byte, 32>>(a_value, helpers::PBKDF2_3);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::byte>>(vb_value, helpers::PBKDF2_3);
		EXPECT_TRUE(result);

		result = helpers::compare<std::vector<std::uint8_t>>(vu_value, helpers::PBKDF2_3);
		EXPECT_TRUE(result);

		result = helpers::compare<std::string>(s_value, helpers::PBKDF2_3);
		EXPECT_TRUE(result);
	}

	TEST(HashTests, PBKDF2_4)
	{
		std::array<std::array<std::byte, 64>, 12> PBKDF2_results{};

		PBKDF2_results[0] = hash::PBKDF2<64>(helpers::pass1, helpers::salt1, helpers::num_of_rounds1);
		PBKDF2_results[1] = hash::PBKDF2<64>(helpers::pass1, helpers::salt2, helpers::num_of_rounds1);
		PBKDF2_results[2] = hash::PBKDF2<64>(helpers::pass1, helpers::salt3, helpers::num_of_rounds1);
		PBKDF2_results[3] = hash::PBKDF2<64>(helpers::pass2, helpers::salt1, helpers::num_of_rounds1);
		PBKDF2_results[4] = hash::PBKDF2<64>(helpers::pass2, helpers::salt2, helpers::num_of_rounds1);
		PBKDF2_results[5] = hash::PBKDF2<64>(helpers::pass2, helpers::salt3, helpers::num_of_rounds1);
		PBKDF2_results[6] = hash::PBKDF2<64>(helpers::pass3, helpers::salt1, helpers::num_of_rounds1);
		PBKDF2_results[7] = hash::PBKDF2<64>(helpers::pass3, helpers::salt2, helpers::num_of_rounds1);
		PBKDF2_results[8] = hash::PBKDF2<64>(helpers::pass3, helpers::salt3, helpers::num_of_rounds1);

		PBKDF2_results[9] = hash::PBKDF2<64>(helpers::pass1, helpers::salt3, helpers::num_of_rounds3);
		PBKDF2_results[10] = hash::PBKDF2<64>(helpers::pass2, helpers::salt2, helpers::num_of_rounds3);
		PBKDF2_results[11] = hash::PBKDF2<64>(helpers::pass3, helpers::salt1, helpers::num_of_rounds3);

		for (std::size_t i = 0; i < PBKDF2_results.size(); i++)
		{
			for (std::size_t j = i + 1; j < PBKDF2_results.size(); j++)
			{
				EXPECT_NE(PBKDF2_results[i], PBKDF2_results[j]) << "|| i = " << i << "; j = " << j;
			}
		}
	}
}