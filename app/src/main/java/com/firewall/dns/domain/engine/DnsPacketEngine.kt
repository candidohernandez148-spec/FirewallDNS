package com.firewall.dns.domain.engine

import com.firewall.dns.domain.model.DnsQueryInfo

object DnsPacketEngine {

    /**
     * Parses one standard DNS question without following compression pointers.
     * Queries are untrusted network input: every length and header field is
     * validated before it is read or used to construct a response.
     */
    fun parseDnsQuery(dns: ByteArray): DnsQueryInfo? {
        // DNS header (12 bytes), at least one label/root byte and QTYPE/QCLASS.
        if (dns.size < 17) return null

        val flags = readU16(dns, 2)
        val questionCount = readU16(dns, 4)
        // This engine handles standard queries only, never DNS responses or
        // UPDATE/NOTIFY/etc. A single question is the supported wire format.
        if ((flags and 0x8000) != 0 || (flags and 0x7800) != 0 || questionCount != 1) {
            return null
        }

        var pos = 12
        var encodedNameLength = 1 // Include the terminating root label.
        val labels = ArrayList<String>()

        while (pos < dns.size) {
            val length = dns[pos].toInt() and 0xFF
            pos++

            if (length == 0) break
            // Compression and reserved label encodings are intentionally
            // rejected; a query name must consist of ordinary DNS labels.
            if ((length and 0xC0) != 0 || length > 63) return null
            if (pos + length > dns.size) return null

            encodedNameLength += 1 + length
            if (encodedNameLength > 255) return null

            for (i in pos until pos + length) {
                val octet = dns[i].toInt() and 0xFF
                // DNS host names are represented as ASCII/IDNA on the wire.
                // Reject control bytes, non-ASCII bytes and embedded dots.
                if (octet !in 0x21..0x7E || octet == '.'.code) return null
            }

            labels += String(dns, pos, length, Charsets.US_ASCII).lowercase()
            pos += length
        }

        if (pos > dns.size || labels.isEmpty() || pos + 4 > dns.size) return null

        val questionEnd = pos + 4
        return DnsQueryInfo(labels.joinToString("."), readU16(dns, pos), questionEnd)
    }

    /**
     * Accepts an upstream UDP response only when it matches the exact outstanding
     * question. The response question is parsed independently because responses
     * have QR=1 and must never be passed to parseDnsQuery().
     */
    fun matchesDnsResponse(request: ByteArray, response: ByteArray): Boolean {
        val requestInfo = parseDnsQuery(request) ?: return false
        if (response.size < 12 || readU16(response, 0) != readU16(request, 0)) return false

        val requestFlags = readU16(request, 2)
        val responseFlags = readU16(response, 2)
        if ((responseFlags and 0x8000) == 0 || // QR must identify a response.
            (responseFlags and 0x7800) != (requestFlags and 0x7800) ||
            (responseFlags and 0x0200) != 0 || // Truncated UDP answers are not complete.
            readU16(response, 4) != 1
        ) return false

        val requestQuestionEnd = requestInfo.questionEndOffset
        val responseQuestionEnd = readQuestionEnd(response) ?: return false
        if (responseQuestionEnd - 12 != requestQuestionEnd - 12) return false

        // Compare QNAME case-insensitively, but preserve exact QTYPE and QCLASS.
        for (index in 12 until responseQuestionEnd - 4) {
            val a = request[index].toInt() and 0xFF
            val b = response[index].toInt() and 0xFF
            val lowerA = if (a in 65..90) a + 32 else a
            val lowerB = if (b in 65..90) b + 32 else b
            if (lowerA != lowerB) return false
        }
        return readU16(request, requestQuestionEnd - 4) ==
            readU16(response, responseQuestionEnd - 4) &&
            readU16(request, requestQuestionEnd - 2) ==
            readU16(response, responseQuestionEnd - 2)
    }

    private fun readQuestionEnd(packet: ByteArray): Int? {
        if (packet.size < 17 || readU16(packet, 4) != 1) return null
        var pos = 12
        var nameLength = 1
        var labels = 0
        while (pos < packet.size) {
            val length = packet[pos].toInt() and 0xFF
            pos++
            if (length == 0) break
            if ((length and 0xC0) != 0 || length > 63 ||
                pos + length > packet.size
            ) return null
            nameLength += length + 1
            if (nameLength > 255) return null
            for (index in pos until pos + length) {
                val octet = packet[index].toInt() and 0xFF
                if (octet !in 0x21..0x7E || octet == '.'.code) return null
            }
            labels++
            pos += length
        }
        if (labels == 0 || pos + 4 > packet.size) return null
        return pos + 4
    }

    fun queryTypeToString(qType: Int): String = when (qType) {
        1 -> "A"
        28 -> "AAAA"
        65 -> "HTTPS"
        5 -> "CNAME"
        16 -> "TXT"
        else -> "T$qType"
    }

    fun buildNxDomainResponse(reqDns: ByteArray, qEnd: Int): ByteArray {
        require(reqDns.size >= 12 && qEnd in 17..reqDns.size) {
            "Invalid DNS question boundary"
        }
        val resp = reqDns.copyOfRange(0, qEnd)
        // QR=1, preserve RD, set RA=1 and RCODE=NXDOMAIN.
        val requestFlags = readU16(reqDns, 2)
        val responseFlags = 0x8000 or (requestFlags and 0x0100) or 0x0080 or 0x0003
        resp[2] = (responseFlags ushr 8).toByte()
        resp[3] = responseFlags.toByte()
        resp[6] = 0; resp[7] = 0
        resp[8] = 0; resp[9] = 0
        resp[10] = 0; resp[11] = 0
        return resp
    }

    fun buildIpv4UdpResponse(
        req: ByteArray, reqSrcIp: ByteArray, reqDstIp: ByteArray,
        reqSrcPort: Int, reqDstPort: Int, dnsResp: ByteArray
    ): ByteArray {
        val ipLen = 20
        val udpLen = 8 + dnsResp.size
        val total = ipLen + udpLen
        val res = ByteArray(total)

        res[0] = 0x45.toByte()
        writeU16(res, 2, total)
        res[4] = req[4]; res[5] = req[5]
        res[6] = 0x40.toByte()
        res[8] = 64.toByte()
        res[9] = 17.toByte()
        System.arraycopy(reqDstIp, 0, res, 12, 4)
        System.arraycopy(reqSrcIp, 0, res, 16, 4)
        writeU16(res, 10, onesComplementSum(res, 0, ipLen))

        writeU16(res, 20, reqDstPort)
        writeU16(res, 22, reqSrcPort)
        writeU16(res, 24, udpLen)
        System.arraycopy(dnsResp, 0, res, 28, dnsResp.size)

        val udpSum = ipv4TransportChecksum(reqDstIp, reqSrcIp, 17, res, 20, udpLen)
        writeU16(res, 26, if (udpSum == 0) 0xFFFF else udpSum)
        return res
    }

    fun buildIpv6UdpResponse(
        reqSrcIp: ByteArray, reqDstIp: ByteArray,
        reqSrcPort: Int, reqDstPort: Int, dnsResp: ByteArray
    ): ByteArray {
        val ipLen = 40
        val udpLen = 8 + dnsResp.size
        val res = ByteArray(ipLen + udpLen)

        res[0] = 0x60.toByte()
        writeU16(res, 4, udpLen)
        res[6] = 17.toByte()
        res[7] = 64.toByte()
        System.arraycopy(reqDstIp, 0, res, 8, 16)
        System.arraycopy(reqSrcIp, 0, res, 24, 16)

        writeU16(res, 40, reqDstPort)
        writeU16(res, 42, reqSrcPort)
        writeU16(res, 44, udpLen)
        System.arraycopy(dnsResp, 0, res, 48, dnsResp.size)

        val udpSum = ipv6TransportChecksum(reqDstIp, reqSrcIp, 17, res, 40, udpLen)
        writeU16(res, 46, if (udpSum == 0) 0xFFFF else udpSum)
        return res
    }

    /**
     * Construye el RST correcto para un segmento TCP ya validado por
     * TunTransportPacketParser. No implementa ni sustituye una conexión TCP.
     */
    fun buildTcpRstResponse(
        req: ByteArray,
        packet: ValidatedTunTransportPacket,
    ): ByteArray? {
        if (packet.protocol != 6 || packet.ipTotalLength != req.size) return null
        val tcpOffset = packet.ipHeaderLength
        val tcpHeaderLength = packet.transportHeaderLength
        if (tcpOffset < 20 || tcpOffset + packet.transportLength > req.size) return null

        val receivedFlags = req[tcpOffset + 13].toInt() and 0xff
        // Never answer an incoming RST.
        if ((receivedFlags and 0x04) != 0) return null

        val hasAck = (receivedFlags and 0x10) != 0
        val sequence = readU32(req, tcpOffset + 4)
        val acknowledgment = readU32(req, tcpOffset + 8)
        val dataLength = packet.transportLength - tcpHeaderLength
        val consumesSequence = dataLength.toLong() +
            (if ((receivedFlags and 0x02) != 0) 1L else 0L) +
            (if ((receivedFlags and 0x01) != 0) 1L else 0L)

        val ipLength = if (packet.isIpv6) 40 else 20
        val tcpLength = 20
        val response = ByteArray(ipLength + tcpLength)

        if (packet.isIpv6) {
            response[0] = 0x60
            writeU16(response, 4, tcpLength)
            response[6] = 6
            response[7] = 64
            System.arraycopy(packet.destinationAddress, 0, response, 8, 16)
            System.arraycopy(packet.sourceAddress, 0, response, 24, 16)
        } else {
            response[0] = 0x45
            writeU16(response, 2, ipLength + tcpLength)
            // Preserve the IPv4 identification, set DF and use a fresh TTL.
            response[4] = req[4]
            response[5] = req[5]
            writeU16(response, 6, 0x4000)
            response[8] = 64
            response[9] = 6
            System.arraycopy(packet.destinationAddress, 0, response, 12, 4)
            System.arraycopy(packet.sourceAddress, 0, response, 16, 4)
            writeU16(response, 10, onesComplementSum(response, 0, ipLength))
        }

        val tcp = ipLength
        writeU16(response, tcp, packet.destinationPort)
        writeU16(response, tcp + 2, packet.sourcePort)
        response[tcp + 12] = 0x50 // Data Offset = 5 (20 bytes), no options.

        if (hasAck) {
            // RFC reset construction for an incoming segment with ACK:
            // SEQ = SEG.ACK, RST set, ACK clear.
            writeU32(response, tcp + 4, acknowledgment)
            writeU32(response, tcp + 8, 0L)
            response[tcp + 13] = 0x04
        } else {
            // Without ACK: RST+ACK acknowledges payload plus SYN/FIN sequence space.
            writeU32(response, tcp + 4, 0L)
            writeU32(response, tcp + 8, (sequence + consumesSequence) and 0xffffffffL)
            response[tcp + 13] = 0x14
        }

        val tcpChecksum = if (packet.isIpv6) {
            ipv6TransportChecksum(
                packet.destinationAddress, packet.sourceAddress, 6, response, tcp, tcpLength
            )
        } else {
            ipv4TransportChecksum(
                packet.destinationAddress, packet.sourceAddress, 6, response, tcp, tcpLength
            )
        }
        writeU16(response, tcp + 16, tcpChecksum)
        return response
    }

    fun readU16(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    private fun writeU16(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v ushr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    private fun readU32(b: ByteArray, i: Int): Long =
        ((b[i].toLong() and 0xFF) shl 24) or ((b[i + 1].toLong() and 0xFF) shl 16) or
            ((b[i + 2].toLong() and 0xFF) shl 8) or (b[i + 3].toLong() and 0xFF)

    private fun writeU32(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v ushr 24) and 0xFF).toByte()
        b[i + 1] = ((v ushr 16) and 0xFF).toByte()
        b[i + 2] = ((v ushr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }

    private fun ipv4TransportChecksum(
        src: ByteArray, dst: ByteArray, proto: Int, buf: ByteArray, offset: Int, len: Int
    ): Int {
        var sum = 0
        for (i in 0 until 4 step 2) sum += readU16(src, i) + readU16(dst, i)
        sum += proto + len
        return foldAndInvert(sum + rawWordSum(buf, offset, len))
    }

    private fun ipv6TransportChecksum(
        src: ByteArray, dst: ByteArray, proto: Int, buf: ByteArray, offset: Int, len: Int
    ): Int {
        var sum = 0
        for (i in 0 until 16 step 2) sum += readU16(src, i) + readU16(dst, i)
        sum += (len ushr 16) + (len and 0xFFFF) + proto
        return foldAndInvert(sum + rawWordSum(buf, offset, len))
    }

    private fun onesComplementSum(buf: ByteArray, offset: Int, len: Int): Int =
        foldAndInvert(rawWordSum(buf, offset, len))

    private fun rawWordSum(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += readU16(buf, i)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xFF) shl 8
        return sum
    }

    private fun foldAndInvert(initialSum: Int): Int {
        var sum = initialSum
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }
}
