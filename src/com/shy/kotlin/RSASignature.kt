package com.shy.kotlin

import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * RSA签名验签类
 */
class RSASignature {
    companion object {
        /**
         * 签名算法
         *
         * MD2withRSA / MD5withRSA / SHA1withRSA
         */
        val ALGORITHM = "SHA1WithRSA"

        /**
         * RSA签名
         *
         * @param content    待签名数据
         * @param privateKey 商户私钥
         * @param encode     字符集编码
         * @return 签名值
         */
        fun sign(content: String, privateKey: String, encode: String = Charset.defaultCharset().name()): String? {
            try {// 根据给定的编码密钥创建一个新的 PKCS8EncodedKeySpec。
                val priPKCS8 = PKCS8EncodedKeySpec(Base64.decode(privateKey))
                // 返回转换指定算法的 public/private 关键字的 KeyFactory 对象。
                val keyf = KeyFactory.getInstance(RSAEncrypt.ALGORITHM)
                // 根据提供的密钥规范（密钥材料）生成私钥对象。
                val priKey = keyf.generatePrivate(priPKCS8)
                // 返回实现指定签名算法的 Signature 对象。MD2withRSA / MD5withRSA / SHA1withRSA
                val signature = Signature.getInstance(ALGORITHM)
                // 初始化这个用于签名的对象。
                signature.initSign(priKey)
                // 从指定的偏移量开始，使用指定的 byte 数组更新要签名或验证的数据。
                signature.update(content.toByteArray(charset(encode)))
                // 返回所有已更新数据的签名字节。
                return Base64.encode(signature.sign())
            } catch (e: Exception) {
                e.printStackTrace()
                return null
            }
        }

        /**
         * RSA验签名检查
         *
         * @param content   待签名数据
         * @param sign      签名值
         * @param publicKey 分配给开发商公钥
         * @param encode    字符集编码
         * @return 布尔值
         */
        fun doCheck(content: String, sign: String, publicKey: String, encode: String = Charset.defaultCharset().name()): Boolean {
            try {// 返回转换指定算法的 public/private 关键字的 KeyFactory 对象。
                val keyFactory = KeyFactory.getInstance(RSAEncrypt.ALGORITHM)

                val pubKey = keyFactory.generatePublic(X509EncodedKeySpec(Base64.decode(publicKey)))
                // 返回实现指定签名算法的 Signature 对象。MD2withRSA / MD5withRSA / SHA1withRSA
                val signature = Signature.getInstance(ALGORITHM)
                // 初始化此用于验证的对象。
                signature.initVerify(pubKey)
                // 从指定的偏移量开始，使用指定的 byte 数组更新要签名或验证的数据。
                signature.update(content.toByteArray(charset(encode)))
                // 验证传入的签名。
                return signature.verify(Base64.decode(sign))
            } catch (e: Exception) {
                e.printStackTrace()
                return false
            }
        }
    }
}