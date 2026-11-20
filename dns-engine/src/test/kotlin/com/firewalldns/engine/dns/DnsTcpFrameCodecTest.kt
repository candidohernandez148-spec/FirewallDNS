package com.firewalldns.engine.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTcpFrameCodecTest {
    @Test
    fun waitsForSplitLengthPrefixAndSplitDnsBody() {
        val message = ByteArray(24).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 1
        }
        val frame = DnsTcpFrameCodec.encode(message)

        assertTrue(DnsTcpFrameCodec.decode(frame.copyOfRange(0, 1)) is DnsTcpFrameDecode.Incomplete)
        assertTrue(DnsTcpFrameCodec.decode(frame.copyOfRange(0, 8)) is DnsTcpFrameDecode.Incomplete)
        val decoded = DnsTcpFrameCodec.decode(frame)
        assertTrue(decoded is DnsTcpFrameDecode.Complete)
        decoded as DnsTcpFrameDecode.Complete
        assertEquals(message.size, decoded.message.size)
        assertEquals(message.toList(), decoded.message.toList())
        assertEquals(frame.size, decoded.consumedBytes)
    }

    @Test
    fun extractsMultipleDnsMessagesFromOneCoalescedRead() {
        val first = DnsTcpFrameCodec.encode(ByteArray(12).apply { this[0] = 1 })
        val second = DnsTcpFrameCodec.encode(ByteArray(16).apply { this[0] = 2 })
        val combined = first + second

        val firstDecoded = DnsTcpFrameCodec.decode(combined) as DnsTcpFrameDecode.Complete
        assertEquals(first.size, firstDecoded.consumedBytes)
        val secondDecoded = DnsTcpFrameCodec.decode(
            combined.copyOfRange(firstDecoded.consumedBytes, combined.size)
        ) as DnsTcpFrameDecode.Complete
        assertEquals(16, secondDecoded.message.size)
        assertEquals(2, secondDecoded.message[0].toInt())
    }

    @Test
    fun rejectsLengthPrefixSmallerThanDnsHeader() {
        val result = DnsTcpFrameCodec.decode(byteArrayOf(0, 11))
        assertTrue(result is DnsTcpFrameDecode.Invalid)
    }

    @Test
    fun supportsMaximumUnsignedDnsTcpLength() {
        val message = ByteArray(65_535).apply { this[0] = 0x55 }
        val frame = DnsTcpFrameCodec.encode(message)
        assertEquals(0xff, frame[0].toInt() and 0xff)
        assertEquals(0xff, frame[1].toInt() and 0xff)
        val decoded = DnsTcpFrameCodec.decode(frame) as DnsTcpFrameDecode.Complete
        assertEquals(65_535, decoded.message.size)
    }
}
