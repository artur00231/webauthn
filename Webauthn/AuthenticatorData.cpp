#include "AuthenticatorData.h"

#include "WebAuthnExceptions.h"

#include <CBORLib.h>
#include <Hash.h>

#include <iterator>

webauthn::AuthenticatorData webauthn::AuthenticatorData::fromBin(const std::vector<std::byte>& data)
{
    //37 bytes = hash + flags + signCount
    if (data.size() < 37)
    {
        throw exceptions::FormatException("Invalid AuthenticatorData format");
    }

    AuthenticatorData authenticator_data{};

    std::copy(data.begin(), data.begin() + 32, authenticator_data.RP_ID_hash.begin());

    const auto flags = static_cast<std::uint8_t>(data.at(32));

    authenticator_data.user_present = flags & 1;
    authenticator_data.user_verified = (flags >> 2) & 1;

    bool attested_cred_data_present = (flags >> 6) & 1;
    bool extensions_present = (flags >> 7) & 1;

    authenticator_data.sign_counter = (static_cast<std::uint32_t>(data.at(33)) << 24u) | (static_cast<std::uint32_t>(data.at(34)) << 16u)
        | (static_cast<std::uint32_t>(data.at(35)) << 8u) | (static_cast<std::uint32_t>(data.at(36)));

    std::uint64_t curr_pos{ 37 };

    if (attested_cred_data_present)
    {
        if (data.size() < 18 + curr_pos)
        {
            throw exceptions::FormatException("Invalid AuthenticatorData format");
        }

        AttestedCredentialData attested_credential_data{};

        std::copy(data.begin() + curr_pos, data.begin() + curr_pos + 16, attested_credential_data.AAGUID.begin());
        curr_pos += 16;

        std::size_t key_size = (static_cast<std::size_t>(data.at(curr_pos)) << 8) | static_cast<std::size_t>(data.at(curr_pos + 1));
        curr_pos += 2;

        if (data.size() < key_size + curr_pos)
        {
            throw exceptions::FormatException("Invalid AuthenticatorData format");
        }

        std::copy(data.begin() + curr_pos, data.begin() + curr_pos + key_size, 
            std::back_inserter(attested_credential_data.credential_id.id));
        curr_pos += key_size;

        //KEY
        std::vector<std::byte> public_key_data{};
        std::copy(data.begin() + curr_pos, data.end(), std::back_inserter(public_key_data));

        auto [key_raw, result] = CBOR::CBORHandle::fromBin(public_key_data);
        curr_pos += result.read;
        public_key_data.resize(result.read);

        PublicKey p_key{};
        p_key.public_key_cbor = public_key_data;

        auto crypto_key = crypto::createPublicKey(key_raw);
        if (!crypto_key)
        {
            throw exceptions::DataException("Cannot read public key");
        }

        p_key.public_key = std::move(*crypto_key);

        attested_credential_data.key = std::move(p_key);

        authenticator_data.attested_credential_data = std::move(attested_credential_data);
    }

    if (extensions_present)
    {
        //TODO
    }

    return authenticator_data;
}

std::vector<std::byte> webauthn::AuthenticatorData::toBin()
{
    std::vector<std::byte> data{};
    
    //RP_ID hash
    std::copy(RP_ID_hash.begin(), RP_ID_hash.end(), std::back_inserter(data));

    //Flags
    std::uint8_t flags{ 0 };
    //user present
    flags |= 0b1 * user_present;
    //user verified 
    flags |= 0b100 * user_verified;
    //Attested credential data included
    flags |= 0b1000000 * bool(attested_credential_data);
    //Extension data included
    //TODO
    flags |= 0b10000000 * false;

    data.push_back(static_cast<std::byte>(flags));

    //Signature counter
    std::uint32_t counter = sign_counter;
    data.push_back(static_cast<std::byte>((counter >> 24) & 0xFF));
    data.push_back(static_cast<std::byte>((counter >> 16) & 0xFF));
    data.push_back(static_cast<std::byte>((counter >> 8) & 0xFF));
    data.push_back(static_cast<std::byte>((counter >> 0) & 0xFF));

    if (attested_credential_data)
    {
        //aaguid
        std::copy(attested_credential_data->AAGUID.begin(), attested_credential_data->AAGUID.end(), std::back_inserter(data));

        //credentialId length
        std::uint16_t length = static_cast<std::uint16_t>(attested_credential_data->credential_id.id.size());
        data.push_back(static_cast<std::byte>((length >> 8) & 0xFF));
        data.push_back(static_cast<std::byte>((length >> 0) & 0xFF));

        //credentialId
        std::copy(attested_credential_data->credential_id.id.begin(), attested_credential_data->credential_id.id.end(), std::back_inserter(data));

        //key
        if (attested_credential_data->key)
        {
            std::copy(attested_credential_data->key->public_key_cbor.begin(), attested_credential_data->key->public_key_cbor.end(), std::back_inserter(data));
        }
    }

    return data;
}
