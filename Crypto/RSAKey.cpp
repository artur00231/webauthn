#include "RSAKey.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

webauthn::crypto::RSAKey::RSAKey(RSAKey&& key) noexcept : p_key{ key.p_key }, default_hash{ key.default_hash }
{
    key.p_key = nullptr;
}

webauthn::crypto::RSAKey& webauthn::crypto::RSAKey::operator=(RSAKey&& key) noexcept
{
    std::swap(p_key, key.p_key);
    std::swap(default_hash, key.default_hash);

    return *this;
}

webauthn::crypto::RSAKey::~RSAKey()
{
    if (p_key)
    {
        EVP_PKEY_free(p_key);
        p_key = nullptr;
    }
}

std::optional<webauthn::crypto::RSAKey> webauthn::crypto::RSAKey::create(const std::vector<std::byte>& bin_modulus, const std::vector<std::byte>& bin_exponent)
{
    RSAKey key{};

    std::unique_ptr<OSSL_PARAM_BLD, decltype([](OSSL_PARAM_BLD* ptr) {
            if (ptr) OSSL_PARAM_BLD_free(ptr);})> param_bld{};

    std::unique_ptr<OSSL_PARAM, decltype([](OSSL_PARAM* ptr) {
            if (ptr) OSSL_PARAM_free(ptr);})> params{};

    std::unique_ptr<EVP_PKEY_CTX, decltype([](EVP_PKEY_CTX* ptr) {
            if (ptr) EVP_PKEY_CTX_free(ptr);})> ctx{};


    using bn_ptr = std::unique_ptr<BIGNUM, decltype([](BIGNUM *ptr) {
        if (ptr) BN_free(ptr); })>;

    if (bin_modulus.size() >= std::numeric_limits<int>::max() || bin_exponent.size() >= std::numeric_limits<int>::max())
    {
        return {};
    }

    BIGNUM* tmp{};
    tmp = BN_bin2bn(reinterpret_cast<const unsigned char*>(bin_modulus.data()), static_cast<int>(bin_modulus.size()), nullptr);
    if (tmp == nullptr) return {};
    bn_ptr modulus{ tmp };

    tmp = nullptr;
    tmp = BN_bin2bn(reinterpret_cast<const unsigned char*>(bin_exponent.data()), static_cast<int>(bin_exponent.size()), nullptr);
    if (tmp == nullptr) return {};
    bn_ptr exponent{ tmp };

    param_bld.reset(OSSL_PARAM_BLD_new());
    if (!param_bld) return {};

    auto result = OSSL_PARAM_BLD_push_BN(param_bld.get(), "n", modulus.get());
    if (result != 1) return {};

    result = OSSL_PARAM_BLD_push_BN(param_bld.get(), "e", exponent.get());
    if (result != 1) return {};

    params.reset(OSSL_PARAM_BLD_to_param(param_bld.get()));
    ctx.reset(EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));

    if (!ctx || !params) return {};

    result = EVP_PKEY_fromdata_init(ctx.get());
    if (result <= 0) return {};

    result = EVP_PKEY_fromdata(ctx.get(), &key.p_key, EVP_PKEY_PUBLIC_KEY, params.get());
    if (result <= 0) return {};

    return key;
}

std::optional<bool> webauthn::crypto::RSAKey::verify(const std::string& data, const std::string& signature) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size());
}

std::optional<bool> webauthn::crypto::RSAKey::verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature) const
{
    return verify(reinterpret_cast<const void*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size());
}

std::optional<bool> webauthn::crypto::RSAKey::verify(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size) const
{
    std::unique_ptr < EVP_MD_CTX, decltype([](EVP_MD_CTX* ptr) {
        if (ptr) EVP_MD_CTX_free(ptr); }) > mdctx{ EVP_MD_CTX_new() };

    const EVP_MD* hash_type{ nullptr };
    switch (default_hash)
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
    case COSE::SIGNATURE_HASH::SHA1:
        hash_type = EVP_sha1();
        break;
    default:
        return {};
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype([](EVP_PKEY_CTX* ptr) {
       if (ptr) EVP_PKEY_CTX_free(ptr);})> ctx{};

    ctx.reset(EVP_PKEY_CTX_new(p_key, nullptr));
    if (!ctx) return {};

    auto result = EVP_PKEY_verify_init(ctx.get());
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_signature_md(ctx.get(), hash_type);
    if (result <= 0) return {};

    //ctx_ptr will be freed when mdctx will be freed
    auto ctx_ptr = ctx.release();
    result = EVP_DigestVerifyInit(mdctx.get(), &ctx_ptr, hash_type, nullptr, p_key);
    if (result <= 0)  return {};

    result = EVP_DigestVerifyUpdate(mdctx.get(), data, data_size);
    if (result <= 0) return {};

    result = EVP_DigestVerifyFinal(mdctx.get(), signature, signature_size);

    if (result == 1)
    {
        return true;
    }

    if (result == 0)
    {
        return false;
    }

    return {};
}
