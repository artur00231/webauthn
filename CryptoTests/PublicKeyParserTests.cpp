#include "pch.h"

#include <PublicKey.h>
#include <ECDSAKey.h>
#include <EdDSAKey.h>
#include <RSAKey.h>
#include <Base64.h>

#include <CBORLib.h>

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static const auto key1 = "pQECAyYgASFYIMew+rUTR8zsD6KkkrUTdYrEk7DXxoL50v0MMBf6LIKpIlggpEOcY7WTRQesM/jNtGOSxBjzd4uMIl3erIF6PbWT9hY="s;

		static const auto key2 = "pAEBAycgBiFYINbENIRGqvF8wIwPDt7DC2ojhV8RwBD/c3OQuzloCqIe"s;

		static const auto key3 = "pAEDAzkBACBZAQDbplnM48H8PEgkTSHXy+w1Me6lMCYnPOeV/r7EvRNoGJHbQLzZiJ1mCkKA49slDmFew/JBg8ok5ZAzWU8vBtnxVBbwTc2j00jh6DBlwTAUyrlNW9GLAWZnhv2WeyhW9n2IoqXZDKpw4nW28N9C4MnkgRU3jsNnoBFWXts3BB5kAZ1OibN+sRIYe3VZcUvEjcOwheIcUBYUR3GhytkPLZoa+ptm13pDNYykNLLc5AyawxuAiWy/4OUtWrzw5aF0fXhJ0p04RYTpfmu1fnSzw1P1f7HxrgUr03yzlWlQ+IQksAXEwj5EL5iGvPD3zLeNA29+qnZ1lQ5jETg6bpgB0zqtIUMBAAE="s;
	}

	TEST(PublicKeyParserTests, ECDSAES256)
	{
		auto cbor_data = base64::fromBase64Url<std::vector<std::byte>>(helpers::key1);
		ASSERT_TRUE(cbor_data);

		auto [cbor, load_result] = CBOR::CBORHandle::fromBin(*cbor_data);
		ASSERT_TRUE(cbor);

		auto key = crypto::PublicKey::createPublicKey(cbor);
		ASSERT_TRUE(key);

		auto ecdsa = dynamic_cast<ECDSAKey*>(key->get());

		ASSERT_TRUE(ecdsa);
		EXPECT_EQ(ecdsa->defaultHash(), COSE::SIGNATURE_HASH::SHA256);
	}

	TEST(PublicKeyParserTests, EdDSAEd25519)
	{
		auto cbor_data = base64::fromBase64Url<std::vector<std::byte>>(helpers::key2);
		ASSERT_TRUE(cbor_data);

		auto [cbor, load_result] = CBOR::CBORHandle::fromBin(*cbor_data);
		ASSERT_TRUE(cbor);

		auto key = crypto::PublicKey::createPublicKey(cbor);
		ASSERT_TRUE(key);

		auto ecdsa = dynamic_cast<EdDSAKey*>(key->get());

		ASSERT_TRUE(ecdsa);
	}

	TEST(PublicKeyParserTests, RS256)
	{
		auto cbor_data = base64::fromBase64Url<std::vector<std::byte>>(helpers::key3);
		ASSERT_TRUE(cbor_data);

		auto [cbor, load_result] = CBOR::CBORHandle::fromBin(*cbor_data);
		ASSERT_TRUE(cbor);

		auto key = crypto::PublicKey::createPublicKey(cbor);
		ASSERT_TRUE(key);

		auto rsa = dynamic_cast<RSAKey*>(key->get());

		ASSERT_TRUE(rsa);
	}
}