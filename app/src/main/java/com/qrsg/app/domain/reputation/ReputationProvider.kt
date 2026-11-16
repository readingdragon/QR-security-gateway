package com.qrsg.app.domain.reputation

/** Remote reputation is separate from Level 1 heuristic risk. */
interface ReputationProvider {
    suspend fun checkUrl(rawUrl: String): ReputationResult
}

sealed interface ReputationResult {
    /** One or more matches returned by the external threat list. */
    data class KnownThreat(
        val threatTypes: Set<String>,
        val checkedAtEpochMs: Long,
        val fromCache: Boolean = false,
    ) : ReputationResult

    /** No match in the provider's lists. NOT a guarantee that a URL is safe. */
    data class NoKnownThreat(
        val checkedAtEpochMs: Long,
        val fromCache: Boolean = false,
    ) : ReputationResult

    data class Unavailable(val reason: ReputationFailure) : ReputationResult

    /** The application deliberately did not contact a provider. */
    data class Skipped(val reason: SkipReason) : ReputationResult
}

enum class ReputationFailure {
    NOT_CONFIGURED,
    NETWORK,
    RATE_LIMITED,
    AUTHENTICATION,
    PROVIDER_ERROR,
    MALFORMED_RESPONSE,
}

enum class SkipReason {
    NOT_A_WEB_URL,
    NON_PUBLIC_DESTINATION,
    URL_CONTAINS_USER_INFO,
    AMBIGUOUS_NUMERIC_HOST,
}
