package com.firewall.dns.domain.engine

import com.firewall.dns.domain.model.DnsQueryInfo

object DnsPacketEngine {

    fun parseDnsQuery(dns: ByteArray): DnsQueryInfo? {
        if (dns.size < 17) return null
        var pos = 12
        val sb = StringBuilder()

        while (pos < dns.size) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) {
                pos += 1
                break
            }
            if ((len and 0xC0) == 0xC0) return null
            pos += 1
            if (pos + len > dns.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(dns, pos, len, Charsets.US_ASCII))
            pos += len
        }

        if (pos + 4 > dns.size || sb.isEmpty()) return null
        return DnsQueryInfo(sb.toString(), readU16(dns, pos), pos + 4)
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
        val resp = reqDns.copyOfRange(0, qEnd)
        resp[2] = 0x81.toByte()
        resp[3] = 0x83.toByte()
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

    private fun readU16(buf: ByteArray, offset: Int): Int {
        return ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
    }

    private fun writeU16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }

    private fun onesComplementSum(buf: ByteArray, start: Int, length: Int): Int {
        var sum = 0
        var i = start
        while (i + 1 < start + length) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < start + length) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum and 0xFFFF
    }

    private fun ipv4TransportChecksum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, payload: ByteArray, offset: Int, length: Int): Int {
        val pseudo = ByteArray(12)
        System.arraycopy(srcIp, 0, pseudo, 0, 4)
        System.arraycopy(dstIp, 0, pseudo, 4, 4)
        pseudo[8] = 0
        pseudo[9] = protocol.toByte()
        pseudo[10] = ((length ushr 8) and 0xFF).toByte()
        pseudo[11] = (length and 0xFF).toByte()

        var sum = 0
        for (i in pseudo.indices step 2) {
            if (i + 1 < pseudo.size) sum += ((pseudo[i].toInt() and 0xFF) shl 8) or (pseudo[i + 1].toInt() and 0xFF)
        }
        for (i in offset until offset + length step 2) {
            if (i + 1 < payload.size) {
                sum += ((payload[i].toInt() and 0xFF) shl 8) or (payload[i + 1].toInt() and 0xFF)
            }
        }
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF)
    }

    private fun ipv6TransportChecksum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, payload: ByteArray, offset: Int, length: Int): Int {
        val pseudo = ByteArray(40)
        System.arraycopy(srcIp, 0, pseudo, 0, 16)
        System.arraycopy(dstIp, 0, pseudo, 16, 16)
        pseudo[32] = 0
        pseudo[33] = 0
        pseudo[34] = 0
        pseudo[35] = 0
        pseudo[36] = ((length ushr 24) and 0xFF).toByte()
        pseudo[37] = ((length ushr 16) and 0xFF).toByte()
        pseudo[38] = ((length ushr 8) and 0xFF).toByte()
        pseudo[39] = (length and 0xFF).toByte()

        var sum = 0
        for (i in pseudo.indices step 2) {
            if (i + 1 < pseudo.size) sum += ((pseudo[i].toInt() and 0xFF) shl 8) or (pseudo[i + 1].toInt() and 0xFF)
        }
        for (i in offset until offset + length step 2) {
            if (i + 1 < payload.size) {
                sum += ((payload[i].toInt() and 0xFF) shl 8) or (payload[i + 1].toInt() and 0xFF)
            }
        }
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF)
    }
}
