package com.qrsg.app.data.reputation

import com.google.protobuf.CodedInputStream

internal object SafeBrowsingProtobufDecoder {

    data class Decoded(
        val threatTypes: Set<String>,
        val cacheDurationMs: Long
    )

    fun decode(body: ByteArray): Decoded {
        val input = CodedInputStream.newInstance(body)
        val types = linkedSetOf<String>()
        var ttl = 0L
        var knownField = false

        while (true) {
            when (val tag = input.readTag()) {
                0 -> break

                10 -> {
                    knownField = true
                    types.addAll(readThreat(input.readByteArray()))
                }

                18 -> {
                    knownField = true
                    ttl = readDuration(input.readByteArray())
                }

                else -> require(input.skipField(tag)) {
                    "Invalid protobuf end-group"
                }
            }
        }

        require(body.isEmpty() || knownField) {
            "Unexpected Safe Browsing response"
        }

        return Decoded(types, ttl)
    }

    private fun readThreat(body: ByteArray): Set<String> {
        val input = CodedInputStream.newInstance(body)
        var hasUrl = false
        val types = linkedSetOf<String>()

        while (true) {
            when (val tag = input.readTag()) {
                0 -> break

                10 -> {
                    hasUrl = input.readStringRequireUtf8().isNotEmpty()
                }

                16 -> {
                    types.add(threatName(input.readEnum()))
                }

                18 -> {
                    val packed = CodedInputStream.newInstance(
                        input.readByteArray()
                    )

                    while (!packed.isAtEnd) {
                        types.add(threatName(packed.readEnum()))
                    }
                }

                else -> require(input.skipField(tag)) {
                    "Invalid threat field"
                }
            }
        }

        require(hasUrl && types.isNotEmpty()) {
            "Incomplete threat"
        }

        return types
    }

    private fun threatName(id: Int): String = when (id) {
        1 -> "MALWARE"
        2 -> "SOCIAL_ENGINEERING"
        3 -> "UNWANTED_SOFTWARE"
        4 -> "POTENTIALLY_HARMFUL_APPLICATION"
        0 -> throw IllegalArgumentException("Unspecified threat type")
        else -> "UNKNOWN_THREAT_TYPE_$id"
    }

    private fun readDuration(body: ByteArray): Long {
        val input = CodedInputStream.newInstance(body)
        var seconds = 0L
        var nanos = 0

        while (true) {
            when (val tag = input.readTag()) {
                0 -> break
                8 -> seconds = input.readInt64()
                16 -> nanos = input.readInt32()
                else -> require(input.skipField(tag)) {
                    "Invalid duration field"
                }
            }
        }

        require(
            seconds in 0..31_536_000L &&
            nanos in 0..999_999_999
        ) {
            "Invalid cache duration"
        }

        return seconds * 1000L + nanos / 1_000_000L
    }
}
