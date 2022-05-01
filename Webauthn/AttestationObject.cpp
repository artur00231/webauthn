#include "AttestationObject.h"

#include "WebAuthnExceptions.h"
#include "Attestation.h"
#include "AuthenticatorData.h"
#include <CBORLib.h>

webauthn::AttestationObject webauthn::AttestationObject::fromCbor(const std::vector<std::byte>& data)
{
	using namespace std::string_literals;

	AttestationObject attestation_object{};

	auto [attestation_object_raw, result] = CBOR::CBORHandle::fromBin(data);

	if (!attestation_object_raw)
	{
		throw exceptions::FormatException{ "Invalid format: E:" + std::to_string(std::to_underlying(result.error.code)) + "; L:" + std::to_string(result.error.position)};
	}

	auto map_arr = CBOR::getMapArray(attestation_object_raw);
	if (!map_arr)
	{
		throw exceptions::FormatException{ "Invalid format: not map" };
	}
	for (auto&& map_elem : *map_arr)
	{
		//We expect only strings as keys
		auto key = CBOR::getString(map_elem->key);

		if (key == "fmt")
		{
			const auto format = CBOR::getString(map_elem->value).and_then([](std::string_view text) {
				return AttestationFactory::getFormat(text);
				}).or_else([]() -> std::optional<Attestation::Format> {
					throw exceptions::DataException{ "Invalid value of fmt" };
				});

			attestation_object.format = *format;
		}
		else if (key == "authData")
		{
			auto data = CBOR::getByteString(map_elem->value);
			
			if (!data) 
			{
				throw exceptions::DataException{ "Invalid value of authData" };
			}

			attestation_object.authenticator_data = AuthenticatorData::fromBin(*data);
		}
		else
		{
			//Unknown key, ignore
		}
	}

	//if (!maybe_fmt)
	//{
	//	throw exceptions::FormatException{ "Invalid format" };
	//}

	//attestation_object.format = maybe_fmt.value();

	//TODO create attestation


	return attestation_object;
}

std::vector<std::byte> webauthn::AttestationObject::toCbor() const
{
	return std::vector<std::byte>();
}
