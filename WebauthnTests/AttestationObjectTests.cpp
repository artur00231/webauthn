#include "pch.h"

#include "../Webauthn/AttestationObject.h"
#include "../Crypto/Base64.h"
#include "../Crypto/Hash.h"

#include <iostream>

namespace webauthn
{
	namespace helpers
	{
		using namespace std::string_literals;

		auto attestation_object = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjE6OigMGfkOiVfr_NFhth65_18t1hxC6VA81Sw5PU2eJJFAAAABAAAAAAAAAAAAAAAAAAAAAAAhnVwuOwqcONt06pQ_1-zXfHvX68QvF1EHszBMgd3YxuIohDVIKMxIYVvS5FSlc0_yCotKOhHeCplbX5kR3QQ3mGlAQIDJiABIVggb6RAOt8ujb7kA_H5IUDU55WSiPyIL3MYtMZ_SZcbOKoiWCDk-aBKAGMtx_g6p4rwDmR9PrZDbFavLv4uYNc2NErwyg"s;
	}

	TEST(AttestationObjectTests, AttestationObject1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::attestation_object);

		ASSERT_TRUE(decoded.has_value());

		auto attestation_object = AttestationObject::fromCbor(*decoded);

		EXPECT_EQ(attestation_object.format, Attestation::Format::None);

		EXPECT_TRUE(attestation_object.authenticator_data.user_present);
		EXPECT_TRUE(attestation_object.authenticator_data.user_verified);
		EXPECT_EQ(attestation_object.authenticator_data.sign_counter, 4);

		auto RP_ID_hash = crypto::hash::SHA256("test_application"s);
		EXPECT_EQ(attestation_object.authenticator_data.RP_ID_hash, RP_ID_hash);

		ASSERT_TRUE(attestation_object.authenticator_data.attested_credential_data);
		
		std::array<std::byte, 16> AAGUID{};
		EXPECT_EQ(attestation_object.authenticator_data.attested_credential_data->AAGUID, AAGUID);
	}
}