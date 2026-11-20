package com.firewall.dns.domain.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class TunTransportPacketParserTest {
    @Test
    fun validatesTcpIpv4AndIpv6WithMandatoryChecksums() {
        val ipv4 = tcpPacket(ipv6 = false, flags = 0x02, sequence = 100, acknowledgment = 0)
        val parsed4 = TunTransportPacketParser.parse(ipv4)
        assertNotNull(parsed4)
        assertEquals(6, parsed4?.protocol)
        assertEquals(53000, parsed4?.sourcePort)
        assertEquals(53, parsed4?.destinationPort)

        val ipv6 = tcpPacket(ipv6 = true, flags = 0x02, sequence = 100, acknowledgment = 0)
        val parsed6 = TunTransportPacketParser.parse(ipv6)
        assertNotNull(parsed6)
        assertEquals(true, parsed6?.isIpv6)
    }

    @Test
    fun validatesIpv4UdpZeroChecksumAndIpv6UdpMandatoryChecksum() {
        val ipv4 = udpPacket(ipv6 = false, zeroChecksum = true)
        val parsed4 = TunTransportPacketParser.parse(ipv4)
        assertNotNull(parsed4)
        assertEquals(17, parsed4?.protocol)
        assertEquals(53, parsed4?.destinationPort)

        val ipv6 = udpPacket(ipv6 = true, zeroChecksum = false)
        assertNotNull(TunTransportPacketParser.parse(ipv6))
        val zeroIpv6 = udpPacket(ipv6 = true, zeroChecksum = true)
        assertNull(TunTransportPacketParser.parse(zeroIpv6))
    }

    @Test
    fun rejectsIpv4FragmentsAndBadUdpChecksums() {
        val fragment = udpPacket(ipv6 = false, zeroChecksum = true).apply {
            this[6] = 0x20
            this[10] = 0
            this[11] = 0
        }
        put16(fragment, 10, checksum(fragment, 0, 20))
        assertNull(TunTransportPacketParser.parse(fragment))

        val corrupt = udpPacket(ipv6 = true, zeroChecksum = false).apply {
            this[48] = (this[48].toInt() xor 0x7f).toByte()
        }
        assertNull(TunTransportPacketParser.parse(corrupt))
    }

    @Test
    fun rejectsInvalidTcpDataOffsetAndChecksum() {
        val badOffset = tcpPacket(false, 0x02, 1, 0).apply { this[32] = 0x40 }
        assertNull(TunTransportPacketParser.parse(badOffset))

        val badChecksum = tcpPacket(false, 0x02, 1, 0).apply { this[36] = (this[36].toInt() xor 1).toByte() }
        assertNull(TunTransportPacketParser.parse(badChecksum))
        val omittedChecksum = tcpPacket(false, 0x02, 1, 0).apply { this[36] = 0; this[37] = 0 }
        assertNull(TunTransportPacketParser.parse(omittedChecksum))
    }

    @Test
    fun buildsCorrectRstAckForSynAndCorrectRstForAckSegment() {
        val syn = tcpPacket(false, flags = 0x02, sequence = 100, acknowledgment = 0, payload = byteArrayOf(1, 2, 3))
        val parsedSyn = TunTransportPacketParser.parse(syn)!!
        val rstAck = DnsPacketEngine.buildTcpRstResponse(syn, parsedSyn)!!
        val parsedResponse = TunTransportPacketParser.parse(rstAck)!!
        assertEquals(53, parsedResponse.sourcePort)
        assertEquals(53000, parsedResponse.destinationPort)
        assertEquals(0x14, rstAck[33].toInt() and 0xff)
        assertEquals(104L, readU32(rstAck, 28))

        val ack = tcpPacket(false, flags = 0x10, sequence = 300, acknowledgment = 900)
        val parsedAck = TunTransportPacketParser.parse(ack)!!
        val rst = DnsPacketEngine.buildTcpRstResponse(ack, parsedAck)!!
        assertEquals(0x04, rst[33].toInt() and 0xff)
        assertEquals(900L, readU32(rst, 24))
        assertEquals(0L, readU32(rst, 28))
        assertNotNull(TunTransportPacketParser.parse(rst))
    }

    @Test
    fun doesNotAnswerRstAndHandlesIpv6Checksum() {
        val incomingRst = tcpPacket(false, flags = 0x04, sequence = 1, acknowledgment = 0)
        val parsedRst = TunTransportPacketParser.parse(incomingRst)!!
        assertNull(DnsPacketEngine.buildTcpRstResponse(incomingRst, parsedRst))

        val syn6 = tcpPacket(true, flags = 0x02, sequence = 7, acknowledgment = 0)
        val parsed6 = TunTransportPacketParser.parse(syn6)!!
        val response6 = DnsPacketEngine.buildTcpRstResponse(syn6, parsed6)!!
        assertNotNull(TunTransportPacketParser.parse(response6))
        assertEquals(0x14, response6[53].toInt() and 0xff)
    }

    private fun udpPacket(ipv6: Boolean, zeroChecksum: Boolean): ByteArray {
        val ipLength = if (ipv6) 40 else 20
        val udpLength = 8 + 12
        val packet = ByteArray(ipLength + udpLength)
        if (ipv6) {
            packet[0] = 0x60
            put16(packet, 4, udpLength)
            packet[6] = 17
            packet[7] = 64
            packet[8] = 0xfd.toByte()
            packet[23] = 2
            packet[24] = 0xfd.toByte()
            packet[39] = 1
        } else {
            packet[0] = 0x45
            put16(packet, 2, packet.size)
            put16(packet, 6, 0x4000)
            packet[8] = 64
            packet[9] = 17
            packet[12] = 10
            packet[15] = 2
            packet[16] = 10
            packet[19] = 1
        }
        val udp = ipLength
        put16(packet, udp, 53000)
        put16(packet, udp + 2, 53)
        put16(packet, udp + 4, udpLength)
        for (i in udp + 8 until packet.size) packet[i] = i.toByte()
        if (!zeroChecksum) {
            put16(packet, udp + 6, transportChecksum(packet, ipv6, udp, udpLength, 17))
        }
        if (!ipv6) put16(packet, 10, checksum(packet, 0, 20))
        return packet
    }

    private fun tcpPacket(
        ipv6: Boolean,
        flags: Int,
        sequence: Long,
        acknowledgment: Long,
        payload: ByteArray = byteArrayOf(),
    ): ByteArray {
        val ipLength = if (ipv6) 40 else 20
        val tcpLength = 20 + payload.size
        val packet = ByteArray(ipLength + tcpLength)
        if (ipv6) {
            packet[0] = 0x60
            put16(packet, 4, tcpLength)
            packet[6] = 6
            packet[7] = 64
            packet[8] = 0xfd.toByte()
            packet[23] = 2
            packet[24] = 0xfd.toByte()
            packet[39] = 1
        } else {
            packet[0] = 0x45
            put16(packet, 2, packet.size)
            put16(packet, 6, 0x4000)
            packet[8] = 64
            packet[9] = 6
            packet[12] = 10
            packet[15] = 2
            packet[16] = 10
            packet[19] = 1
        }
        val tcp = ipLength
        put16(packet, tcp, 53000)
        put16(packet, tcp + 2, 53)
        put32(packet, tcp + 4, sequence)
        put32(packet, tcp + 8, acknowledgment)
        packet[tcp + 12] = 0x50
        packet[tcp + 13] = flags.toByte()
        put16(packet, tcp + 14, 4096)
        payload.copyInto(packet, tcp + 20)
        val checksum = transportChecksum(packet, ipv6, tcp, tcpLength)
        put16(packet, tcp + 16, checksum)
        if (!ipv6) put16(packet, 10, checksum(packet, 0, 20))
        return packet
    }

    private fun transportChecksum(
        packet: ByteArray, ipv6: Boolean, offset: Int, length: Int, protocol: Int = 6
    ): Int {
        var sum = 0L
        val srcOffset = if (ipv6) 8 else 12
        val addressLength = if (ipv6) 16 else 4
        for (i in 0 until addressLength step 2) {
            sum += u16(packet, srcOffset + i).toLong()
            sum += u16(packet, srcOffset + addressLength + i).toLong()
        }
        if (ipv6) {
            sum += (length ushr 16).toLong() + (length and 0xffff).toLong() + protocol.toLong()
        } else {
            sum += protocol.toLong() + length.toLong()
        }
        sum += rawSum(packet, offset, length)
        return fold(sum)
    }

    private fun checksum(packet: ByteArray, offset: Int, length: Int): Int =
        fold(rawSum(packet, offset, length))

    private fun rawSum(packet: ByteArray, offset: Int, length: Int): Long {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += u16(packet, i).toLong()
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xff).toLong() shl 8
        return sum
    }

    private fun fold(initial: Long): Int {
        var sum = initial
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    private fun put16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private fun put32(packet: ByteArray, offset: Int, value: Long) {
        packet[offset] = (value ushr 24).toByte()
        packet[offset + 1] = (value ushr 16).toByte()
        packet[offset + 2] = (value ushr 8).toByte()
        packet[offset + 3] = value.toByte()
    }

    private fun readU32(packet: ByteArray, offset: Int): Long =
        ((packet[offset].toLong() and 0xff) shl 24) or
            ((packet[offset + 1].toLong() and 0xff) shl 16) or
            ((packet[offset + 2].toLong() and 0xff) shl 8) or
            (packet[offset + 3].toLong() and 0xff)
}
