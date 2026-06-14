#include <gtest/gtest.h>

#include "PiSubmarine/Security/Nonce/Api/ErrorCode.h"
#include "PiSubmarine/Security/Nonce/Openssl/Provider.h"

namespace PiSubmarine::Security::Nonce::Openssl
{
    TEST(ProviderTest, RejectsZeroPrefixSize)
    {
        EXPECT_THROW((Provider(Provider::Config{.PrefixSize = 0, .CounterSize = 8})), std::invalid_argument);
    }

    TEST(ProviderTest, RejectsCounterSizeAboveEightBytes)
    {
        EXPECT_THROW((Provider(Provider::Config{.PrefixSize = 4, .CounterSize = 9})), std::invalid_argument);
    }

    TEST(ProviderTest, NextReturnsConfiguredSize)
    {
        Provider provider(Provider::Config{.PrefixSize = 4, .CounterSize = 8});

        const auto result = provider.Next();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->Value.size(), 12U);
    }

    TEST(ProviderTest, NextProducesUniqueCounterSuffixes)
    {
        Provider provider(Provider::Config{.PrefixSize = 4, .CounterSize = 8});

        const auto first = provider.Next();
        const auto second = provider.Next();

        ASSERT_TRUE(first.has_value());
        ASSERT_TRUE(second.has_value());
        EXPECT_NE(first->Value, second->Value);
        EXPECT_EQ(
            std::vector<std::byte>(first->Value.begin(), first->Value.begin() + 4),
            std::vector<std::byte>(second->Value.begin(), second->Value.begin() + 4));
    }

    TEST(ProviderTest, ReportsNonceExhaustion)
    {
        Provider provider(Provider::Config{.PrefixSize = 4, .CounterSize = 1});

        for (int index = 0; index < 256; ++index)
        {
            ASSERT_TRUE(provider.Next().has_value());
        }

        const auto exhausted = provider.Next();

        ASSERT_FALSE(exhausted.has_value());
        EXPECT_EQ(exhausted.error().Cause, make_error_code(Api::ErrorCode::NonceExhausted));
    }
}
