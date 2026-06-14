#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "PiSubmarine/Security/Nonce/Api/IProvider.h"

namespace PiSubmarine::Security::Nonce::Openssl
{
    class Provider final : public Api::IProvider
    {
    public:
        struct Config
        {
            std::size_t PrefixSize = 4;
            std::size_t CounterSize = sizeof(std::uint64_t);
        };

        explicit Provider(Config config = {});

        [[nodiscard]] Error::Api::Result<Api::Nonce> Next() override;

    private:
        Config m_Config;
        std::vector<std::byte> m_Prefix;
        std::uint64_t m_NextCounter = 0;
        bool m_Exhausted = false;
    };
}
