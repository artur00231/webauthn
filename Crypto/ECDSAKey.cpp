#include "ECDSAKey.h"

#include <memory>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

std::optional<webauthn::crypto::ECDSAKey> webauthn::crypto::ECDSAKey::create(const std::string& hex_x, const std::string& hex_y, const ECDSA_EC ec)
{
    ECDSAKey ECDSA_key{};

    switch (ec)
    {
    case ECDSA_EC::P256:
        ECDSA_key.eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        break;
    case ECDSA_EC::P384:
        ECDSA_key.eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
        break;
    case ECDSA_EC::P521:
        ECDSA_key.eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
        break;
    case ECDSA_EC::secp256k1:
        ECDSA_key.eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        break;
    default:
        return {};
    }

    auto group = EC_KEY_get0_group(ECDSA_key.eckey);
    if (!group) return {};

    std::unique_ptr<EC_POINT, decltype([](EC_POINT* ptr) {
            if (ptr) EC_POINT_free(ptr);
        })> pub_key{ EC_POINT_new(group) };

    if (!pub_key) return {};

    using BN_ptr = std::unique_ptr<BIGNUM, decltype([](BIGNUM* ptr) {
            if (ptr) BN_free(ptr);
        })>;

    std::unique_ptr<BN_CTX, decltype([](BN_CTX* ptr) {
            if (ptr) BN_CTX_free(ptr);
        })> bn_ctx{ BN_CTX_new() };

    if (!bn_ctx) return {};

    BIGNUM* num{ nullptr };
    auto result = BN_hex2bn(&num, hex_x.c_str());
    if (result == 0 || num == nullptr) return {};
    BN_ptr x{ num };

    num = nullptr;
    result = BN_hex2bn(&num, hex_y.c_str());
    if (result == 0 || num == nullptr) return {};
    BN_ptr y{ num };

    result = EC_POINT_set_affine_coordinates(group, pub_key.get(), x.get(), y.get(), bn_ctx.get());
    if (result != 1) return {};

    result = EC_KEY_set_public_key(ECDSA_key.eckey, pub_key.get());
    if (result != 1) return {};

    return ECDSA_key;
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const std::string& data, const std::string& signature, const SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size, const SIGNATURE_HASH hash) const
{
    std::unique_ptr<EVP_PKEY, decltype([](EVP_PKEY* ptr) {
            if (ptr) EVP_PKEY_free(ptr);
        })> key{ EVP_PKEY_new() };

    auto result = EVP_PKEY_set1_EC_KEY(key.get(), eckey);
    if (result != 1) return {};

    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ptr) {
            if (ptr) EVP_MD_CTX_free(ptr);
        })> mdctx{ EVP_MD_CTX_new() };

    const EVP_MD* hash_type{ nullptr };
    switch (hash)
    {
    case SIGNATURE_HASH::SHA256:
        hash_type = EVP_sha256();
        break;
    case SIGNATURE_HASH::SHA384:
        hash_type = EVP_sha384();
        break;
    case SIGNATURE_HASH::SHA512:
        hash_type = EVP_sha512();
        break;
    default:
        return {};
    }

    result = EVP_DigestVerifyInit(mdctx.get(), nullptr, hash_type, nullptr, key.get());
    if (result != 1) return {};

    result = EVP_DigestVerifyUpdate(mdctx.get(), data, data_size);
    if (result != 1) return {};


    result = EVP_DigestVerifyFinal(mdctx.get(), signature, signature_size);
    if (result == 1) 
    {
        return true;
    }

    return false;
}

webauthn::crypto::ECDSAKey::ECDSAKey(ECDSAKey&& key) noexcept : eckey{ key.eckey }
{
    key.eckey = nullptr;
}

webauthn::crypto::ECDSAKey& webauthn::crypto::ECDSAKey::operator=(ECDSAKey&& key) noexcept
{
    std::swap(eckey, key.eckey);

    return *this;
}

webauthn::crypto::ECDSAKey::~ECDSAKey()
{
    if (eckey)
    {
        EC_KEY_free(eckey);
        eckey = nullptr;
    }
}
