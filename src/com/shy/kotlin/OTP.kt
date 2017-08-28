package com.shy.kotlin

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class OTP {
    companion object {
        // 这些都是用来计算和校验位。
        private val doubleDigits = intArrayOf(0, 2, 4, 6, 8, 1, 3, 5, 7, 9)

        /**
         * Calculates the checksum using the credit card algorithm.
         * This algorithm has the advantage that it detects any single
         * mistyped digit and any single transposition of
         * adjacent digits.
         *
         *
         * 使用信用卡的校验和计算算法。
         * 该算法的优点在于它检测到任何错误数字和任何单一的转位相邻的数字。
         *
         * @param num    the number to calculate the checksum for 计算校验和的数
         * @param digits number of significant places in the number 在相当数量的名额
         * @return the checksum of num 数字的校验和
         */
        fun calcChecksum(num: Long, digits: Int): Int {
            var num = num
            var digits = digits
            var doubleDigit = true
            var total = 0
            while (0 < digits--) {
                var digit = (num % 10).toInt()
                num /= 10
                if (doubleDigit) {
                    digit = doubleDigits[digit]
                }
                total += digit
                doubleDigit = !doubleDigit
            }
            var result = total % 10
            if (result > 0) {
                result = 10 - result
            }
            return result
        }


        /**
         * This method uses the JCE to provide the HMAC-SHA-1
         * algorithm.
         * HMAC computes a Hashed Message Authentication Code and
         * in this case SHA1 is the hash algorithm used.
         *
         *
         * 该方法使用JCE提供hmac-sha-1算法。
         * HMAC计算一个散列消息认证码，在这种情况下是使用SHA1哈希算法。
         *
         * @param keyBytes the bytes to use for the HMAC-SHA-1 key 字节用于hmac-sha-1关键
         * @param text     the message or text to be authenticated. 该消息或文本被认证。
         * @throws NoSuchAlgorithmException if no provider makes
         * either HmacSHA1 or HMAC-SHA-1
         * digest algorithms available.
         * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-1 key.
         */

        private fun hmac_sha1(keyBytes: ByteArray, text: ByteArray): ByteArray {
            var hmacSha1: Mac
            try {
                hmacSha1 = Mac.getInstance("HmacSHA1")
            } catch (nsae: NoSuchAlgorithmException) {
                hmacSha1 = Mac.getInstance("HMAC-SHA-1")
            }

            val macKey = SecretKeySpec(keyBytes, "RAW")
            hmacSha1.init(macKey)
            return hmacSha1.doFinal(text)
        }


        private val DIGITS_POWER = intArrayOf(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)// 0 1  2   3    4     5      6       7        8


        /**
         * This method generates an OTP value for the given
         * set of parameters. 这种方法生成的给定的参数设置OTP值。
         *
         * @param secret           the shared secret
         * @param movingFactor     the counter, time, or other value that
         * changes on a per use basis.
         * @param codeDigits       the number of digits in the OTP, not
         * including the checksum, if any.
         * @param addChecksum      a flag that indicates if a checksum digit
         * should be appended to the OTP.
         * @param truncationOffset the offset into the MAC result to
         * begin truncation.  If this value is out of
         * the range of 0 ... 15, then dynamic
         * truncation  will be used.
         * Dynamic truncation is when the last 4
         * bits of the last byte of the MAC are
         * used to determine the start offset.
         * @return A numeric String in base 10 that includes
         * [] digits plus the optional checksum
         * digit if requested.
         * @throws NoSuchAlgorithmException if no provider makes
         * either HmacSHA1 or HMAC-SHA-1
         * digest algorithms available.
         * @throws InvalidKeyException      The secret provided was not
         * a valid HMAC-SHA-1 key.
         */
        fun generateOTP(secret: ByteArray,
                        movingFactor: Long,
                        codeDigits: Int,
                        addChecksum: Boolean,
                        truncationOffset: Int): String {
            var movingFactor = movingFactor
            // put movingFactor value into text byte array
            var result: String
            val digits = if (addChecksum) codeDigits + 1 else codeDigits
            val text = ByteArray(8)
            for (i in text.indices.reversed()) {
                text[i] = (movingFactor and 0xff).toByte()
                movingFactor = movingFactor shr 8
            }


            // compute hmac hash
            val hash = hmac_sha1(secret, text)


            // put selected bytes into result int
            var offset = hash[hash.size - 1].toInt() and 0xf
            if (0 <= truncationOffset && truncationOffset < hash.size - 4) {
                offset = truncationOffset
            }
            val binary = (hash[offset].toInt() and 0x7f shl 24) or
                    (hash[offset + 1].toInt() and 0xff shl 16) or
                    (hash[offset + 2].toInt() and 0xff shl 8) or
                    (hash[offset + 3].toInt() and 0xff)


            var otp = binary % DIGITS_POWER[codeDigits]
            if (addChecksum) {
                otp = otp * 10 + calcChecksum(otp.toLong(), codeDigits)
            }
            result = Integer.toString(otp)
            while (result.length < digits) {
                result = "0" + result
            }
            return result
        }
    }
}