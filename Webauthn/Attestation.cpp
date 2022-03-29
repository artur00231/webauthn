#include "Attestation.h"
#include "WebAuthnExceptions.h"

#include "TMPAttestation.h"


#include <nlohmann/json.hpp>

std::optional<webauthn::Attestation::Format> webauthn::AttestationFactory::getFormat(std::string_view fmt)
{
	if (fmt == "none")
	{
		return webauthn::Attestation::Format::None;
	}

	return {};
}

std::unique_ptr<webauthn::Attestation> webauthn::AttestationFactory::praseAttestation(const std::vector<::std::byte>& cbor)
{
	using namespace std::string_literals;

	nlohmann::json attestation_object_raw{};
	try {
		attestation_object_raw = nlohmann::json::from_cbor(cbor);
	} catch (const nlohmann::json::exception& exception)
	{
		throw webauthn::exceptions::FormatException(exception.what());
	}

	try {
		std::string format = attestation_object_raw.at("fmt");

		if (format == "none")
		{
			//TODO
		}
		else if (format == "tpm")
		{
			auto& attestation_raw = attestation_object_raw.at("attStmt");
			auto& authData_raw = attestation_object_raw.at("authData");

			auto tmp_attestation = TMPAttestation::parseJSON(attestation_raw);

			return std::make_unique<TMPAttestation>(tmp_attestation);
		}
		else
		{
			throw webauthn::exceptions::FormatException("Invalid or unsupported attestation format");
		}
	}
	catch (const nlohmann::json::exception& exception)
	{
		throw webauthn::exceptions::FormatException(exception.what() +
		"\nCannot determine attestation format or data is not formatted correctly."s);
	}
}