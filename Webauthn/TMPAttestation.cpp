#include "TMPAttestation.h"

#include "WebAuthnExceptions.h"

webauthn::TMPAttestation webauthn::TMPAttestation::parseJSON(const nlohmann::json& data)
{
    try {
        TMPAttestation attestation{};

        attestation.version = data.at("ver");
        std::int32_t algorithm = data.at("alg");

        if (!webauthn::COSE::isCOSE_ALGORITHM(algorithm))
        {
            throw webauthn::exceptions::DataException("Invalid or unsupported algorithm");
        }
        attestation.algorithm = static_cast<webauthn::COSE::COSE_ALGORITHM>(algorithm);

        auto& cert_info_arr = data.at("certInfo").get_binary();
        std::copy(cert_info_arr.cbegin(), cert_info_arr.cend(), std::back_inserter(attestation.cert_info));

        auto& pub_area_arr = data.at("pubArea").get_binary();
        std::copy(pub_area_arr.cbegin(), pub_area_arr.cend(), std::back_inserter(attestation.pub_area));

        auto& sig_arr = data.at("sig").get_binary();
        std::copy(sig_arr.cbegin(), sig_arr.cend(), std::back_inserter(attestation.sig));

        if (data.contains("x5c"))
        {
            auto& x5c_arr_arr = data.at("x5c");

            for (auto& x5c_arr_o : x5c_arr_arr)
            {
                attestation.x5c.emplace_back();
                auto& x5c_arr = x5c_arr_o.get_binary();
                std::transform(x5c_arr.cbegin(), x5c_arr.cend(), std::back_inserter(attestation.x5c.back()),
                    [](auto x) { return static_cast<std::byte>(x); });
            }
        }

        if (data.contains("ecdaaKeyId"))
        {
            //TODO
            attestation.ecdaaKeyId = { 0 };
        }

        return attestation;
    }
    catch (const nlohmann::json::exception& exception)
    {
        throw webauthn::exceptions::FormatException(exception.what());
    }
}
