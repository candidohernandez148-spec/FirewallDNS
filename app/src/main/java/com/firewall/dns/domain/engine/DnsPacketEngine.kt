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

    fun buildTcpRstResponse(
        req: ByteArray, isIpv6: Boolean, reqIhl: Int, srcIp: ByteArray, dstIp: ByteArray
    ): ByteArray? {
        val tcpFlags = req[reqIhl + 13].toInt() and 0xFF
        if ((tcpFlags and 0x04) != 0) return null

        val isSyn = (tcpFlags and 0x02) != 0
        val hasAck = (tcpFlags and 0x10) != 0
        val reqTcpDataOff = ((req[reqIhl + 12].toInt() ushr 4) and 0x0F) * 4
        val reqPayloadLen = (req.size - reqIhl - reqTcpDataOff).coerceAtLeast(0)
        val reqSeq = readU32(req, reqIhl + 4)
        val reqAck = readU32(req, reqIhl + 8)

        val ipLen = if (isIpv6) 40 else 20
        val tcpLen = 20
        val res = ByteArray(ipLen + tcpLen)

        if (isIpv6) {
            res[0] = 0x60.toByte()
            writeU16(res, 4, tcpLen)
            res[6] = 6.toByte()
            res[7] = 64.toByte()
            System.arraycopy(dstIp, 0, res, 8, 16)
            System.arraycopy(srcIp, 0, res, 24, 16)
        } else {
            res[0] = 0x45.toByte()
            writeU16(res, 2, ipLen + tcpLen)
            res[6] = 0x40.toByte()
            res[8] = 64.toByte()
            res[9] = 6.toByte()
            System.arraycopy(dstIp, 0, res, 12, 4)
            System.arraycopy(srcIp, 0, res, 16, 4)
            writeU16(res, 10, onesComplementSum(res, 0, ipLen))
        }

        res[ipLen] = req[reqIhl + 2]; res[ipLen + 1] = req[reqIhl + 3]
        res[ipLen + 2] = req[reqIhl]; res[ipLen + 3] = req[reqIhl + 1]

        if (hasAck) {
            writeU32(res, ipLen + 4, reqAck)
            writeU32(res, ipLen + 8, 0L)
            res[ipLen + 13] = 0x04.toByte()
        } else {
            writeU32(res, ipLen + 4, 0L)
            val ackVal = (reqSeq + reqPayloadLen + (if (isSyn) 1L else 0L)) and 0xFFFFFFFFL
            writeU32(res, ipLen + 8, ackVal)
            res[ipLen + 13] = 0x14.toByte()
        }
        res[ipLen + 12] = 0x50.toByte()

        val tcpSum = if (isIpv6) {
            ipv6TransportChecksum(dstIp, srcIp, 6, res, ipLen, tcpLen)
        } else {
            ipv4TransportChecksum(dstIp, srcIp, 6, res, ipLen, tcpLen)
        }
        writeU16(res, ipLen + 16, tcpSum)
        return res
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
