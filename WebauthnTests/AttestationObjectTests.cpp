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

		auto attestation_object = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjE6OigMGfkOiVfr/NFhth65/18t1hxC6VA81Sw5PU2eJJFAAAABAAAAAAAAAAAAAAAAAAAAAAAQP3r3W6zF66CKi7yT9HztDGlSdsXVesAprXdiE1b+gt+Fly74PLnaD8whnGArf66WYgNdNBMOQYarAELk1Q/UcmlAQIDJiABIVggx7D6tRNHzOwPoqSStRN1isSTsNfGgvnS/QwwF/osgqkiWCCkQ5xjtZNFB6wz+M20Y5LEGPN3i4wiXd6sgXo9tZP2Fg=="s;
		auto attestation_object_key_id = "/evdbrMXroIqLvJP0fO0MaVJ2xdV6wCmtd2ITVv6C34WXLvg8udoPzCGcYCt/rpZiA100Ew5BhqsAQuTVD9RyQ=="s;
	}

	TEST(AttestationObjectTests, AttestationObject1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::attestation_object);
		auto decoded_key_id = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::attestation_object_key_id);

		ASSERT_TRUE(decoded.has_value());
		ASSERT_TRUE(decoded_key_id.has_value());

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

		EXPECT_EQ(attestation_object.authenticator_data.attested_credential_data->credential_id.id, *decoded_key_id);
	}
}