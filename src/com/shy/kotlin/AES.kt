package com.shy.kotlin

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AES {
    companion object {

        val ECB = "AES/ECB/PKCS5Padding"
        val CBC = "AES/CBC/PKCS5Padding"
        val ALGORITHM = "AES"

        /**
         * @return 返回随机秘钥
         */
        fun genKey(): String? {
            try {
                // 返回生成指定算法的秘密密钥的 KeyGenerator 对象。
                val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
                // 确定的密钥大小 128/192/256
                keyGenerator.init(128)
                // 生成一个密钥。 返回基本编码格式的密钥，如果此密钥不支持编码，则返回 null。
                return Base64.encode(keyGenerator.generateKey().encoded)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
                return null
            }

        }

        /**
         * ECB加密
         *
         * @param data 加密数据
         * @param key  秘钥
         * @return  密文
         */
        fun ecbEncrypt(data: String, key: String): String? {
            try {// 1. 传入算法，实例化一个加解密器
                val cipher = Cipher.getInstance(ECB)
                // 2. 传入加密模式和密钥，初始化一个加密器
                cipher.init(Cipher.ENCRYPT_MODE, secretKey(key))
                // 3. 调用doFinal方法加密
                return Base64.encode(cipher.doFinal(data.toByteArray()))
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此加密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("明文长度非法")
            } catch (e: BadPaddingException ) {
                throw Exception("明文数据已损坏")
            }
        }

        /**
         * ECB解密
         *
         * @param data 密文数据
         * @param key  秘钥
         * @return  解密数据
         */
        fun ecbDecrypt(data: String, key: String): String? {
            try {// 1. 传入算法，实例化一个加解密器
                val cipher = Cipher.getInstance(ECB)
                // 2. 传入解密模式和密钥，初始化一个加密器
                cipher.init(Cipher.DECRYPT_MODE, secretKey(key))
                return String(cipher.doFinal(Base64.decode(data)))
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此解密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("密文长度非法")
            } catch (e: BadPaddingException ) {
                throw Exception("密文数据已损坏")
            }

        }

        /**
         * CBC加密
         *
         * @param data  加密数据
         * @param key   秘钥
         * @param iv
         * @return      密文
         */
        fun cbcEncrypt(data: String, key: String, iv: String): String? {
            try {// CBC 模式中的 DES 和使用 OAEP 编码操作的 RSA 密码。
                val ivParameterSpec = IvParameterSpec(iv(iv))
                val cipher = Cipher.getInstance(CBC)
                cipher.init(Cipher.ENCRYPT_MODE, secretKey(key), ivParameterSpec)
                return Base64.encode(cipher.doFinal(data.toByteArray()))
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此加密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("明文长度非法")
            } catch (e: BadPaddingException ) {
                throw Exception("明文数据已损坏")
            }
        }

        /**
         * CBC 解密
         *
         * @param data  密文数据
         * @param key   秘钥
         * @param iv
         * @return      解密数据
         */
        fun cbcDecrypt(data: String, key: String, iv: String): String? {
            try {
                val ivParameterSpec = IvParameterSpec(iv(iv))
                val cipher = Cipher.getInstance(CBC)
                cipher.init(Cipher.DECRYPT_MODE, secretKey(key), ivParameterSpec)
                return String(cipher.doFinal(Base64.decode(data)))
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此解密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("密文长度非法")
            } catch (e: BadPaddingException ) {
                throw Exception("密文数据已损坏")
            }
        }

        /**
         * 还原密钥
         *
         * @param key
         * @return
         */
        private fun secretKey(key: String): SecretKey {
            return SecretKeySpec(Base64.decode(key), ALGORITHM)
        }

        /**
         * 取前16个字节
         */
        private fun iv(rsa: String): ByteArray {
            return Arrays.copyOfRange(rsa.toByteArray(), 0, 16)
        }
    }
}