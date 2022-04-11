#include "ECDSAKey.h"

#include <memory>
#include <algorithm>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

std::optional<webauthn::crypto::ECDSAKey> webauthn::crypto::ECDSAKey::create(const std::vector<std::byte>& bin_x,
    const std::vector<std::byte>& bin_y, const COSE::ECDSA_EC ec)
{
    ECDSAKey ECDSA_key{};

    std::vector<unsigned char> public_key_data{};
    public_key_data.push_back(POINT_CONVERSION_UNCOMPRESSED);
    std::transform(bin_x.begin(), bin_x.end(), std::back_inserter(public_key_data),
        [](auto x) { return static_cast<unsigned char>(x); });
    std::transform(bin_y.begin(), bin_y.end(), std::back_inserter(public_key_data),
        [](auto x) { return static_cast<unsigned char>(x); });

    std::unique_ptr<OSSL_PARAM_BLD, decltype([](OSSL_PARAM_BLD* ptr) {
            if (ptr) OSSL_PARAM_BLD_free(ptr);})> param_bld{};

    std::unique_ptr<OSSL_PARAM, decltype([](OSSL_PARAM* ptr) {
            if (ptr) OSSL_PARAM_free(ptr);})> params{};

    std::unique_ptr<EVP_PKEY_CTX, decltype([](EVP_PKEY_CTX* ptr) {
            if (ptr) EVP_PKEY_CTX_free(ptr);})> ctx{};

    param_bld.reset(OSSL_PARAM_BLD_new());
    if (param_bld == nullptr) return {};

    switch (ec)
    {
    case COSE::ECDSA_EC::P256:
        if (!OSSL_PARAM_BLD_push_utf8_string(param_bld.get(), "group", "prime256v1", 0)) return {};
        break;
    case COSE::ECDSA_EC::P384:
        if (!OSSL_PARAM_BLD_push_utf8_string(param_bld.get(), "group", "secp384r1", 0)) return {};
        break;
    case COSE::ECDSA_EC::P521:
        if (!OSSL_PARAM_BLD_push_utf8_string(param_bld.get(), "group", "secp521r1", 0)) return {};
        break;
    case COSE::ECDSA_EC::secp256k1:
        if (!OSSL_PARAM_BLD_push_utf8_string(param_bld.get(), "group", "secp256k1", 0)) return {};
        break;
    default:
        return {};
    }
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld.get(), "pub", public_key_data.data(), public_key_data.size())) return {};

    params.reset(OSSL_PARAM_BLD_to_param(param_bld.get()));

    ctx.reset(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));

    if (ctx == nullptr || params == nullptr) return {};
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) return {};
    if (EVP_PKEY_fromdata(ctx.get(), &ECDSA_key.p_key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) return {};

    return ECDSA_key;
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const std::string& data, const std::string& signature, const COSE::SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const COSE::SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::ECDSAKey::verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size, const COSE::SIGNATURE_HASH hash) const
{
    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ptr) {
            if (ptr) EVP_MD_CTX_free(ptr);
        })> mdctx{ EVP_MD_CTX_new() };

    const EVP_MD* hash_type{ nullptr };
    switch (hash)
    {
    case COSE::SIGNATURE_HASH::SHA256:
        hash_type = EVP_sha256();
        break;
    case COSE::SIGNATURE_HASH::SHA384:
        hash_type = EVP_sha384();
        break;
    case COSE::SIGNATURE_HASH::SHA512:
        hash_type = EVP_sha512();
        break;
    default:
        return {};
    }

    auto result = EVP_DigestVerifyInit(mdctx.get(), nullptr, hash_type, nullptr, p_key);
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

webauthn::crypto::ECDSAKey::ECDSAKey(ECDSAKey&& key) noexcept : p_key{ key.p_key }
{
    key.p_key = nullptr;
}

webauthn::crypto::ECDSAKey& webauthn::crypto::ECDSAKey::operator=(ECDSAKey&& key) noexcept
{
    std::swap(p_key, key.p_key);

    return *this;
}

webauthn::crypto::ECDSAKey::~ECDSAKey()
{
    if (p_key)
    {
        EVP_PKEY_free(p_key);
        p_key = nullptr;
    }
}
