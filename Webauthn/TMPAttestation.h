#pragma once

#include "Attestation.h"
#include <COSE.h>

//#include <nlohmann/json.hpp>
#include <cstddef>
#include <vector>

namespace webauthn
{
	class TMPAttestation : public Attestation
	{
	public:
		std::string version{};

		crypto::COSE::COSE_ALGORITHM algorithm{};
		std::vector<std::vector<std::byte>> x5c{};
		std::vector<std::uint8_t> ecdaaKeyId{};
		std::vector<std::uint8_t> key_id{};
		std::vector<std::uint8_t> sig{};
		std::vector<std::uint8_t> cert_info{};
		std::vector<std::uint8_t> pub_area{};


		//static TMPAttestation parseJSON(const nlohmann::json& data);

		virtual bool canAttest() const override { return true; }
	};
}

