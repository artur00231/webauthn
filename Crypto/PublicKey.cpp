#include "PublicKey.h"

#include "ECDSAKey.h"

std::optional<std::unique_ptr<webauthn::crypto::PublicKey>> webauthn::crypto::createPublicKey(const std::vector<std::byte>& cbor)
{
    auto [handle, result] = CBOR::CBORHandle::fromBin(cbor);
    if (!handle) return {};

    return createPublicKey(handle);
}

std::optional<webauthn::crypto::ECDSAKey> createECDSA(webauthn::CBOR::CBORHandle handle, webauthn::crypto::COSE::SIGNATURE_HASH hash,
    std::optional<webauthn::crypto::COSE::ECDSA_EC> ec = {});

std::optional<std::unique_ptr<webauthn::crypto::PublicKey>> webauthn::crypto::createPublicKey(CBOR::CBORHandle handle)
{
    auto map_arr = CBOR::getMapArray(handle);
    if (!map_arr) return {};

    std::optional<COSE::COSE_ALGORITHM> alg{};
    std::optional<COSE::KEY_TYPE> key_type{};

    //Check for algorithm type
    for (auto& elem : *map_arr)
    {
        auto value = CBOR::getIntegral<int>(elem->key);
        if (!value) {
            continue;
        }

        if (*value == 1)
        {
            auto value = CBOR::getIntegral<int>(elem->value);
            if (!value) return {};

            if (!COSE::isCOSE_KeyType(*value)) return {};

            key_type = static_cast<COSE::KEY_TYPE>(*value);
        }

        if (*value == 3)
        {
            auto value = CBOR::getIntegral<int>(elem->value);
            if (!value) return {};

            if (!COSE::isCOSE_ALGORITHM(*value)) return {};

            alg = static_cast<COSE::COSE_ALGORITHM>(*value);
        }
    }

    if (!alg) return {};

    switch (*alg)
    {
    case COSE::COSE_ALGORITHM::ES256:
        if (!key_type || *key_type != COSE::KEY_TYPE::EC) return {};
        return createECDSA(handle, COSE::SIGNATURE_HASH::SHA256).and_then([](webauthn::crypto::ECDSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::ECDSAKey>(std::move(key)));
            });
        break;
    case COSE::COSE_ALGORITHM::ES384:
        if (!key_type || *key_type != COSE::KEY_TYPE::EC) return {};
        return createECDSA(handle, COSE::SIGNATURE_HASH::SHA384).and_then([](webauthn::crypto::ECDSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::ECDSAKey>(std::move(key)));
            });
        break;
    case COSE::COSE_ALGORITHM::ES512:
        if (!key_type || *key_type != COSE::KEY_TYPE::EC) return {};
        return createECDSA(handle, COSE::SIGNATURE_HASH::SHA512).and_then([](webauthn::crypto::ECDSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::ECDSAKey>(std::move(key)));
            });
        break;
    case COSE::COSE_ALGORITHM::ES256K:
        if (!key_type || *key_type != COSE::KEY_TYPE::EC) return {};
        return createECDSA(handle, COSE::SIGNATURE_HASH::SHA512, COSE::ECDSA_EC::secp256k1).and_then([](webauthn::crypto::ECDSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::ECDSAKey>(std::move(key)));
            });
        break;

    default:
        return {};
        break;
    }

    [[unlikely]]
    return {};
}

std::optional<webauthn::crypto::ECDSAKey> createECDSA(webauthn::CBOR::CBORHandle handle, webauthn::crypto::COSE::SIGNATURE_HASH hash,
    std::optional<webauthn::crypto::COSE::ECDSA_EC> ec)
{
    auto map_arr = webauthn::CBOR::getMapArray(handle);
    if (!map_arr) return {};

    std::optional<std::vector<std::byte>> bin_x{};
    std::optional<std::vector<std::byte>> bin_y{};

    //Check for algorithm type
    for (auto& elem : *map_arr)
    {
        auto value = webauthn::CBOR::getIntegral<int>(elem->key);

        if (!value)
        {
            continue;
        }

        if (*value == -1 && !ec)
        {
            auto value = webauthn::CBOR::getIntegral<int>(elem->value);
            if (!value) return {};

            if (!webauthn::crypto::COSE::isCOSE_EC(*value)) return {};

            ec = static_cast<webauthn::crypto::COSE::ECDSA_EC>(*value);
        }

        if (*value == -2 && !bin_x)
        {
            bin_x = std::move(webauthn::CBOR::getByteString(elem->value));
        }

        if (*value == -3 && !bin_y)
        {
            bin_y = std::move(webauthn::CBOR::getByteString(elem->value));
        }
    }

    if (!ec || !bin_x || !bin_y) return {};

    auto key = webauthn::crypto::ECDSAKey::create(*bin_x, *bin_y, *ec);
    if (!key) return {};

    key->setDefaultHash(hash);

    return key;
}
