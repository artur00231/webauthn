#include "PublicKey.h"

#ifdef PUBLICKEY_CRYPTO_FORCE_FULL
#undef PUBLICKEY_CRYPTO_LITE
#endif // !PUBLICKEY_CRYPTO_FORCE_FULL

#ifndef PUBLICKEY_CRYPTO_LITE
#include "ECDSAKey.h"
#include "EdDSAKey.h"
#include "RSAKey.h"
#endif // !PUBLICKEY_CRYPTO_LITE

std::optional<std::unique_ptr<webauthn::crypto::PublicKey>> webauthn::crypto::PublicKey::createPublicKey(const std::vector<std::byte>& cbor)
{
    auto [handle, result] = CBOR::CBORHandle::fromBin(cbor);
    if (!handle) return {};

    return createPublicKey(handle);
}

#ifndef PUBLICKEY_CRYPTO_LITE
namespace webauthn::crypto
{
    static std::optional<webauthn::crypto::ECDSAKey> createECDSA(webauthn::CBOR::CBORHandle handle, webauthn::crypto::COSE::SIGNATURE_HASH hash,
        std::optional<webauthn::crypto::COSE::ECDSA_EC> ec = {});

    static std::optional<webauthn::crypto::EdDSAKey> createEdDSA(webauthn::CBOR::CBORHandle handle);

    static std::optional<webauthn::crypto::RSAKey> createRSA(webauthn::CBOR::CBORHandle handle, COSE::COSE_ALGORITHM rsa_algorithm);
}

std::optional<std::unique_ptr<webauthn::crypto::PublicKey>> webauthn::crypto::PublicKey::createPublicKey(CBOR::CBORHandle handle)
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
    case COSE::COSE_ALGORITHM::EdDSA:
        if (!key_type || *key_type != COSE::KEY_TYPE::OKP) return {};
        return createEdDSA(handle).and_then([](webauthn::crypto::EdDSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::EdDSAKey>(std::move(key)));
            });
        break;
    case COSE::COSE_ALGORITHM::RS1: [[fallthrough]];
    case COSE::COSE_ALGORITHM::RS256: [[fallthrough]];
    case COSE::COSE_ALGORITHM::RS384: [[fallthrough]];
    case COSE::COSE_ALGORITHM::RS512: [[fallthrough]];
    case COSE::COSE_ALGORITHM::PS256: [[fallthrough]];
    case COSE::COSE_ALGORITHM::PS384: [[fallthrough]];
    case COSE::COSE_ALGORITHM::PS512:
        if (!key_type || *key_type != COSE::KEY_TYPE::RSA) return {};
        return createRSA(handle, *alg).and_then([](webauthn::crypto::RSAKey&& key)
            {
                return std::make_optional(std::make_unique<webauthn::crypto::RSAKey>(std::move(key)));
            });
        break;

    default:
        return {};
        break;
    }

    [[unlikely]]
    return {};
}

std::optional<webauthn::crypto::ECDSAKey> webauthn::crypto::createECDSA(webauthn::CBOR::CBORHandle handle, webauthn::crypto::COSE::SIGNATURE_HASH hash,
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

            if (!webauthn::crypto::COSE::isCOSE_ECDSA_EC(*value)) return {};

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

std::optional<webauthn::crypto::EdDSAKey> webauthn::crypto::createEdDSA(webauthn::CBOR::CBORHandle handle)
{
    auto map_arr = webauthn::CBOR::getMapArray(handle);
    if (!map_arr) return {};

    std::optional<std::vector<std::byte>> bin_x{};
    std::optional<COSE::EdDSA_EC> ec{};

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

            if (!webauthn::crypto::COSE::isCOSE_EdDSA_EC(*value)) return {};

            ec = static_cast<webauthn::crypto::COSE::EdDSA_EC>(*value);
        }

        if (*value == -2 && !bin_x)
        {
            bin_x = std::move(webauthn::CBOR::getByteString(elem->value));
        }
    }

    if (!ec || !bin_x) return {};

    auto key = webauthn::crypto::EdDSAKey::create(*bin_x, *ec);
    if (!key) return {};

    return key;
}

std::optional<webauthn::crypto::RSAKey> webauthn::crypto::createRSA(webauthn::CBOR::CBORHandle handle, COSE::COSE_ALGORITHM rsa_algorithm)
{
    auto map_arr = webauthn::CBOR::getMapArray(handle);
    if (!map_arr) return {};

    std::optional<std::vector<std::byte>> modulus{};
    std::optional<std::vector<std::byte>> exponent{};
    std::optional<COSE::COSE_ALGORITHM> algorithm{};

    //Check for algorithm type
    for (auto& elem : *map_arr)
    {
        auto value = webauthn::CBOR::getIntegral<int>(elem->key);

        if (!value)
        {
            continue;
        }

        if (*value == -1 && !modulus)
        {
            modulus = std::move(webauthn::CBOR::getByteString(elem->value));
        }

        if (*value == -2 && !exponent)
        {
            exponent = std::move(webauthn::CBOR::getByteString(elem->value));
        }
    }

    if (!modulus || !exponent) return {};

    auto key = webauthn::crypto::RSAKey::create(*modulus, *exponent, rsa_algorithm);
    if (!key) return {};

    return key;
}
#else
    std::optional<std::unique_ptr<webauthn::crypto::PublicKey>> webauthn::crypto::PublicKey::createPublicKey(CBOR::CBORHandle handle)
    {
        return std::make_unique(EmptyPublicKey{});
    }
#endif // !PUBLICKEY_CRYPTO_LITE