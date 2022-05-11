#include "WebAuthnImplFactory.h"

#include "WebAuthnWinHello.h"
#include "Webauthnlibfido2.h"

#include <utility>
#include <cstdlib>
#include <array>
#include <ranges>
#include <algorithm>


namespace webauthn::impl
{
    class WebAuthnWinHello;
    class Webauthnlibfido2;
}

namespace helpers
{
    using namespace std::string_literals;

    template<typename T>
    static std::unique_ptr<webauthn::impl::WebAuthnImpl> makeImpl(T* t = static_cast<T*>(nullptr))
    {
        using impl = std::decay_t<decltype(*t)>;
        return std::make_unique<impl>(impl{});
    }

    template<typename T = webauthn::impl::WebAuthnWinHello, typename = void>
    struct WebAuthnWinHelloAvaiable : std::false_type {
        template<typename = void>
        static inline std::unique_ptr<webauthn::impl::WebAuthnImpl> create() { return {}; }
    };
    template<typename T>
    struct WebAuthnWinHelloAvaiable<T, std::void_t<decltype(sizeof(T))>> : std::true_type {
        template<typename = void>
        static inline std::unique_ptr<webauthn::impl::WebAuthnImpl> create() {
            return makeImpl<webauthn::impl::WebAuthnWinHello>();
        }
    };
    static constexpr bool isWebAuthnWinHelloAvaiable = WebAuthnWinHelloAvaiable<>::value;

    template<typename T = webauthn::impl::Webauthnlibfido2, typename = void>
    struct Webauthnlibfido2Avaiable : std::false_type {
        static inline std::unique_ptr<webauthn::impl::WebAuthnImpl> create() { return {}; }
    };
    template<typename T>
    struct Webauthnlibfido2Avaiable<T, std::void_t<decltype(sizeof(T))>> : std::true_type {
        static inline std::unique_ptr<webauthn::impl::WebAuthnImpl> create() {
            return makeImpl<webauthn::impl::Webauthnlibfido2>();
        }
    };
    static constexpr bool isWebauthnlibfido2Avaiable = Webauthnlibfido2Avaiable<>::value;

    static std::optional<std::string> getUserImpl()
    {
        auto user_impl = std::getenv(webauthn::WebAuthnImplFactory::environment_variable_name);
        if (user_impl == nullptr)
        {
            return {};
        }

        return { user_impl };
    }

#ifdef _WIN32
    const static std::array<std::string, 2> impl_preferences{ "WebAuthnWinHello"s, "Webauthnlibfido2"s };
#else
    const static std::array<std::string, 1> impl_preferences{ "Webauthnlibfido2"s };
#endif // _WIN32

    std::unique_ptr<webauthn::impl::WebAuthnImpl> createWebAuthnImplFromName(std::string name)
    {
        if (name == "WebAuthnWinHello"s)
        {
            return WebAuthnWinHelloAvaiable<>::create();
        }
        else if (name == "Webauthnlibfido2"s)
        {
            return Webauthnlibfido2Avaiable<>::create();
        }

        return {};
    }

    std::unique_ptr<webauthn::impl::WebAuthnImpl> createInternalWebAuthnImpl()
    {
        const auto& preferences = impl_preferences;
        const auto avaiable = webauthn::WebAuthnImplFactory::getAvaiableImplementations();

        auto impl_to_use = [&preferences, &avaiable]() -> std::optional<std::string> {
            for (auto&& preference : preferences)
            {
                if (std::ranges::find(avaiable, preference) != std::end(avaiable))
                    return preference;
            }
            return std::nullopt;
        }();

        if (!impl_to_use)
            return {};

        return createWebAuthnImplFromName(*impl_to_use);
    }
}

std::unique_ptr<webauthn::impl::WebAuthnImpl> webauthn::WebAuthnImplFactory::createWebAuthnImpl(std::optional<std::string> implementation)
{
    using namespace std::string_literals;

    if (!implementation)
    {
        return helpers::createInternalWebAuthnImpl();
    }
    else
    {
        if (*implementation == "internal"s)
        { 
            return helpers::createInternalWebAuthnImpl();
        }
        else
        {
            return helpers::createWebAuthnImplFromName(*implementation);
        }
    }

    return {};
}

std::vector<std::string> webauthn::WebAuthnImplFactory::getAvaiableImplementations()
{
    using namespace std::string_literals;

    std::vector<std::string> avaiable_implementations{};

    if (helpers::isWebAuthnWinHelloAvaiable)
        avaiable_implementations.push_back("WebAuthnWinHello"s);
    if (helpers::isWebauthnlibfido2Avaiable)
        avaiable_implementations.push_back("Webauthnlibfido2"s);

    return avaiable_implementations;
}
