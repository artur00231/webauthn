#include "pch.h"

#include "../Crypto/PublicKey.h"
#include "../Crypto/ECDSAKey.h"
#include "../Crypto/EdDSAKey.h"
#include "../Crypto/Base64.h"

#include "../CBOR/CBOR.h"

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static const auto key1 = "pQECAyYgASFYIMew+rUTR8zsD6KkkrUTdYrEk7DXxoL50v0MMBf6LIKpIlggpEOcY7WTRQesM/jNtGOSxBjzd4uMIl3erIF6PbWT9hY="s;
	}

	TEST(PublicKeyParserTests, ECDSAES256)
	{
		auto cbor_data = base64::fromBase64Fix<std::vector<std::byte>>(helpers::key1);
		ASSERT_TRUE(cbor_data);

		auto [cbor, load_result] = CBOR::CBORHandle::fromBin(*cbor_data);
		ASSERT_TRUE(cbor);

		auto key = crypto::createPublicKey(cbor);
		ASSERT_TRUE(key);

		auto ecdsa = dynamic_cast<ECDSAKey*>(key->get());

		ASSERT_TRUE(ecdsa);
		EXPECT_EQ(ecdsa->defaultHash(), COSE::SIGNATURE_HASH::SHA256);
	}
}