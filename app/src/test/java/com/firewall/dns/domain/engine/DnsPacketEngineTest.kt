package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketEngineTest {

    @Test
    fun parsesStandardAQuestion() {
        val query = dnsQuery("ExAmPlE.com", qType = 1)

        val parsed = DnsPacketEngine.parseDnsQuery(query)

        assertEquals("example.com", parsed?.domain)
        assertEquals(1, parsed?.qType)
        assertEquals(query.size, parsed?.questionEndOffset)
    }

    @Test
    fun parsesHttpsQuestion() {
        val parsed = DnsPacketEngine.parseDnsQuery(dnsQuery("example.com", qType = 65))
        assertEquals(65, parsed?.qType)
    }

    @Test
    fun rejectsTruncatedHeaderAndQuestion() {
        assertNull(DnsPacketEngine.parseDnsQuery(ByteArray(11)))
        assertNull(DnsPacketEngine.parseDnsQuery(dnsQuery("example.com").copyOf(20)))
    }

    @Test
    fun rejectsResponsePacketAndUnsupportedOpcode() {
        val response = dnsQuery("example.com").apply { this[2] = 0x80.toByte() }
        val update = dnsQuery("example.com").apply { this[2] = 0x28.toByte() }

        assertNull(DnsPacketEngine.parseDnsQuery(response))
        assertNull(DnsPacketEngine.parseDnsQuery(update))
    }

    @Test
    fun rejectsZeroOrMultipleQuestions() {
        val noQuestions = dnsQuery("example.com").apply { this[5] = 0 }
        val multipleQuestions = dnsQuery("example.com").apply { this[5] = 2 }

        assertNull(DnsPacketEngine.parseDnsQuery(noQuestions))
        assertNull(DnsPacketEngine.parseDnsQuery(multipleQuestions))
    }

    @Test
    fun rejectsCompressedAndInvalidLabels() {
        val compressed = ByteArray(18).apply {
            this[5] = 1
            this[12] = 0xC0.toByte()
            this[13] = 0x0C
        }
        val invalidAscii = dnsQuery("example.com").apply { this[13] = 0 }
        assertNull(DnsPacketEngine.parseDnsQuery(compressed))
        assertNull(DnsPacketEngine.parseDnsQuery(invalidAscii))
    }

    @Test
    fun nxdomainResponsePreservesTransactionIdAndRecursionDesired() {
        val query = dnsQuery("example.com").apply {
            this[0] = 0x12
            this[1] = 0x34
        }

        val response = DnsPacketEngine.buildNxDomainResponse(
            query,
            DnsPacketEngine.parseDnsQuery(query)!!.questionEndOffset
        )

        assertEquals(0x12, response[0].toInt() and 0xFF)
        assertEquals(0x34, response[1].toInt() and 0xFF)
        val flags = DnsPacketEngine.readU16(response, 2)
        assertTrue((flags and 0x8000) != 0)
        assertTrue((flags and 0x0100) != 0)
        assertEquals(3, flags and 0x000F)
        assertEquals(query.size, response.size)
    }

    @Test
    fun rejectsInvalidNxdomainBoundary() {
        assertThrows(IllegalArgumentException::class.java) {
            DnsPacketEngine.buildNxDomainResponse(ByteArray(12), 12)
        }
    }

    @Test
    fun acceptsOnlyResponseForMatchingQuestion() {
        val query = dnsQuery("example.com")
        val response = query.copyOf().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
        }

        assertTrue(DnsPacketEngine.matchesDnsResponse(query, response))
    }

    @Test
    fun responseQuestionNameComparisonIsCaseInsensitive() {
        val query = dnsQuery("example.com")
        val response = query.copyOf().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
            this[13] = 'E'.code.toByte()
        }

        assertTrue(DnsPacketEngine.matchesDnsResponse(query, response))
    }

    @Test
    fun rejectsWrongTransactionIdQuestionAndNonResponsePackets() {
        val query = dnsQuery("example.com")
        val valid = query.copyOf().apply { this[2] = 0x81.toByte() }

        assertTrue(DnsPacketEngine.matchesDnsResponse(query, valid))
        assertNullIfFalse(query, valid.copyOf().apply { this[0] = 0x7F })
        assertNullIfFalse(query, valid.copyOf().apply { this[13] = 'x'.code.toByte() })
        assertNullIfFalse(query, query.copyOf())
        assertNullIfFalse(query, valid.copyOf().apply { this[2] = 0x89.toByte() })
        assertNullIfFalse(query, valid.copyOf().apply { this[5] = 2 })
        assertNullIfFalse(query, valid.copyOf().apply { this[valid.lastIndex] = 3 })
    }

    private fun assertNullIfFalse(request: ByteArray, response: ByteArray) {
        assertTrue(!DnsPacketEngine.matchesDnsResponse(request, response))
    }

    private fun dnsQuery(domain: String, qType: Int = 1): ByteArray {
        val labels = domain.split('.')
        val name = labels.flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        }.toByteArray() + byteArrayOf(0)
        return byteArrayOf(
            0x12, 0x34, // transaction id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ) + name + byteArrayOf(
            (qType shr 8).toByte(), qType.toByte(),
            0x00, 0x01 // class IN
        )
    }
}
