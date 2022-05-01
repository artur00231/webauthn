#include "RSAKey.h"

#include <limits>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

webauthn::crypto::RSAKey::RSAKey(RSAKey&& key) noexcept : p_key{ key.p_key }, default_hash{ key.default_hash }, mgf1_hash{ key.mgf1_hash }, padding{ key.padding }
{
    key.p_key = nullptr;
}

webauthn::crypto::RSAKey& webauthn::crypto::RSAKey::operator=(RSAKey&& key) noexcept
{
    std::swap(p_key, key.p_key);
    std::swap(default_hash, key.default_hash);
    std::swap(mgf1_hash, key.mgf1_hash);
    std::swap(padding, key.padding);

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

std::optional<webauthn::crypto::RSAKey> webauthn::crypto::RSAKey::create(const std::vector<std::byte>& bin_modulus, const std::vector<std::byte>& bin_exponent, COSE::COSE_ALGORITHM rsa_alg)
{
    RSAKey key{};

    switch (rsa_alg)
    {
    case webauthn::crypto::COSE::COSE_ALGORITHM::RS1:
        key.default_hash = COSE::SIGNATURE_HASH::SHA1;
        key.padding = Padding::PKCS1_v1_5;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::RS256:
        key.default_hash = COSE::SIGNATURE_HASH::SHA256;
        key.padding = Padding::PKCS1_v1_5;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::RS384:
        key.default_hash = COSE::SIGNATURE_HASH::SHA384;
        key.padding = Padding::PKCS1_v1_5;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::RS512:
        key.default_hash = COSE::SIGNATURE_HASH::SHA512;
        key.padding = Padding::PKCS1_v1_5;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::PS512:
        key.default_hash = COSE::SIGNATURE_HASH::SHA512;
        key.mgf1_hash = COSE::SIGNATURE_HASH::SHA512;
        key.padding = Padding::PSS;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::PS384:
        key.default_hash = COSE::SIGNATURE_HASH::SHA384;
        key.mgf1_hash = COSE::SIGNATURE_HASH::SHA384;
        key.padding = Padding::PSS;
        break;
    case webauthn::crypto::COSE::COSE_ALGORITHM::PS256:
        key.default_hash = COSE::SIGNATURE_HASH::SHA256;
        key.mgf1_hash = COSE::SIGNATURE_HASH::SHA256;
        key.padding = Padding::PSS;
        break;
    default:
        return {};
    }

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
    switch (padding)
    {
    case webauthn::crypto::RSAKey::Padding::PKCS1_v1_5:
        return verifyPKCS1_v1_5(data, data_size, signature, signature_size);
    case webauthn::crypto::RSAKey::Padding::PSS:
        return verifyPSS(data, data_size, signature, signature_size);
    }

    return {};
}

std::optional<bool> webauthn::crypto::RSAKey::verifyPKCS1_v1_5(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size) const
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

    //ctx_ptr will be freed when mdctx will be freed
    auto ctx_ptr = ctx.release();
    auto result = EVP_DigestVerifyInit(mdctx.get(), &ctx_ptr, hash_type, nullptr, p_key);
    if (result <= 0)  return {};

    result = EVP_PKEY_CTX_set_rsa_padding(ctx_ptr, RSA_PKCS1_PADDING);
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_signature_md(ctx_ptr, hash_type);
    if (result <= 0) return {};

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

std::optional<bool> webauthn::crypto::RSAKey::verifyPSS(const void* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size) const
{
    std::unique_ptr < EVP_MD_CTX, decltype([](EVP_MD_CTX* ptr) {
        if (ptr) EVP_MD_CTX_free(ptr); }) > mdctx{ EVP_MD_CTX_new() };

    const EVP_MD* hash_type{ nullptr };
    const EVP_MD* mgf1hash_type{ nullptr };
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

    switch (mgf1_hash)
    {
    case COSE::SIGNATURE_HASH::SHA256:
        mgf1hash_type = EVP_sha256();
        break;
    case COSE::SIGNATURE_HASH::SHA384:
        mgf1hash_type = EVP_sha384();
        break;
    case COSE::SIGNATURE_HASH::SHA512:
        mgf1hash_type = EVP_sha512();
        break;;
    default:
        return {};
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype([](EVP_PKEY_CTX* ptr) {
       if (ptr) EVP_PKEY_CTX_free(ptr);})> ctx{};

    ctx.reset(EVP_PKEY_CTX_new(p_key, nullptr));
    if (!ctx) return {};

    //ctx_ptr will be freed when mdctx will be freed
    auto ctx_ptr = ctx.release();
    auto result = EVP_DigestVerifyInit(mdctx.get(), &ctx_ptr, hash_type, nullptr, p_key);
    if (result <= 0)  return {};

    result = EVP_PKEY_CTX_set_rsa_padding(ctx_ptr, RSA_PKCS1_PSS_PADDING);
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx_ptr, mgf1hash_type);
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_signature_md(ctx_ptr, hash_type);
    if (result <= 0) return {};

    result = EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx_ptr, RSA_PSS_SALTLEN_AUTO);
    if (result <= 0) return {};

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
