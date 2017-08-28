package com.shy.kotlin

import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class RSAEncrypt {
    companion object {
        val ALGORITHM = "RSA"

        /**
         * @return 随机生成密钥对
         */
        fun genKeyPair(): Array<String>? {
            try {
                // 返回生成指定算法的 public/private 密钥对的 KeyPairGenerator 对象。
                val keyPairGen = KeyPairGenerator.getInstance(ALGORITHM)
                // 使用给定的随机源（和默认的参数集合）初始化确定密钥大小的密钥对生成器。
                keyPairGen.initialize(1024, SecureRandom())
                // 生成一个密钥对，保存在keyPair中
                val keyPair = keyPairGen.generateKeyPair()
                return arrayOf(Base64.encode(keyPair.private.encoded)!!, Base64.encode(keyPair.public.encoded)!!)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
                return null
            }

        }

        /**
         * 从字符串中加载公钥
         *
         * @param publicKeyStr 公钥数据字符串
         * @throws Exception 加载公钥时产生的异常
         */
        @Throws(Exception::class)
        fun strToPublicKey(publicKeyStr: String): PublicKey {
            try {
                val buffer = Base64.decode(publicKeyStr)
                // 根据给定的编码密钥创建一个新的 X509EncodedKeySpec
                val keySpec = X509EncodedKeySpec(buffer)
                // 返回转换指定算法的 public/private 关键字的 KeyFactory 对象
                val keyFactory = KeyFactory.getInstance(ALGORITHM)
                // 根据提供的密钥规范（密钥材料）生成公钥对象。
                return keyFactory.generatePublic(keySpec)
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此算法")
            } catch (e: InvalidKeySpecException) {
                throw Exception("公钥非法")
            } catch (e: NullPointerException) {
                throw Exception("公钥数据为空")
            }

        }

        /**
         * 从字符串中加载私钥
         *
         * @param privateKeyStr 私钥数据字符串
         * @throws Exception 加载公钥时产生的异常
         */
        @Throws(Exception::class)
        fun strToPrivateKey(privateKeyStr: String): PrivateKey {
            try {
                val buffer = Base64.decode(privateKeyStr)
                // 根据给定的编码密钥创建一个新的 PKCS8EncodedKeySpec。
                val keySpec = PKCS8EncodedKeySpec(buffer)
                // 返回转换指定算法的 public/private 关键字的 KeyFactory 对象
                val keyFactory = KeyFactory.getInstance(ALGORITHM)
                // 根据提供的密钥规范（密钥材料）生成私钥对象。
                return keyFactory.generatePrivate(keySpec)
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此算法")
            } catch (e: InvalidKeySpecException) {
                throw Exception("私钥非法")
            } catch (e: NullPointerException) {
                throw Exception("私钥数据为空")
            }

        }
//
//        /**
//         * 公钥加密过程
//         *
//         * @param publicKey     公钥
//         * @param plainTextData 明文数据
//         * @return 密文
//         * @throws Exception 加密过程中的异常信息
//         */
//        fun encrypt(publicKey: PublicKey?, plainTextData: ByteArray): ByteArray? {
//            if (publicKey == null) throw Exception("加密公钥为空, 请设置")
//            try {
//                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
//                val cipher = Cipher.getInstance(ALGORITHM)
//                // 用密钥初始化此 Cipher 加密模式
//                cipher.init(Cipher.ENCRYPT_MODE, publicKey)
//                // 加密或解密数据
//                return cipher.doFinal(plainTextData)
//            } catch (e: NoSuchAlgorithmException) {
//                throw Exception("无此加密算法")
//            } catch (e: NoSuchPaddingException) {
//                e.printStackTrace()
//                return null
//            } catch (e: InvalidKeyException) {
//                throw Exception("加密公钥非法,请检查")
//            } catch (e: IllegalBlockSizeException) {
//                throw Exception("明文长度非法")
//            } catch (e: BadPaddingException) {
//                throw Exception("明文数据已损坏")
//            }
//
//        }
//
//        /**
//         * 私钥解密过程
//         *
//         * @param privateKey 私钥
//         * @param cipherData 密文数据
//         * @return 明文
//         * @throws Exception 解密过程中的异常信息
//         */
//        fun decrypt(privateKey: PrivateKey?, cipherData: ByteArray): ByteArray? {
//            if (privateKey == null) throw Exception("解密私钥为空, 请设置")
//            try {
//                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
//                val cipher = Cipher.getInstance(ALGORITHM)
//                // 用密钥初始化此 Cipher 解密模式
//                cipher.init(Cipher.DECRYPT_MODE, privateKey)
//                // 加密或解密数据
//                return cipher.doFinal(cipherData)
//            } catch (e: NoSuchAlgorithmException) {
//                throw Exception("无此解密算法")
//            } catch (e: NoSuchPaddingException) {
//                e.printStackTrace()
//                return null
//            } catch (e: InvalidKeyException) {
//                throw Exception("解密私钥非法,请检查")
//            } catch (e: IllegalBlockSizeException) {
//                throw Exception("密文长度非法")
//            } catch (e: BadPaddingException) {
//                throw Exception("密文数据已损坏")
//            }
//
//        }
//
//        /**
//         * 私钥加密过程
//         *
//         * @param privateKey    私钥
//         * @param plainTextData 明文数据
//         * @return              密文
//         * @throws Exception    加密过程中的异常信息
//         */
//        fun encrypt(privateKey: PrivateKey?, plainTextData: ByteArray): ByteArray? {
//            if (privateKey == null) throw Exception("加密私钥为空, 请设置")
//            try {
//                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
//                val cipher = Cipher.getInstance(ALGORITHM)
//                // 用密钥初始化此 Cipher 加密模式
//                cipher.init(Cipher.ENCRYPT_MODE, privateKey)
//                // 加密或解密数据
//                return cipher.doFinal(plainTextData)
//            } catch (e: NoSuchAlgorithmException) {
//                throw Exception("无此加密算法")
//            } catch (e: NoSuchPaddingException) {
//                e.printStackTrace()
//                return null
//            } catch (e: InvalidKeyException) {
//                throw Exception("加密私钥非法,请检查")
//            } catch (e: IllegalBlockSizeException) {
//                throw Exception("明文长度非法")
//            } catch (e: BadPaddingException) {
//                throw Exception("明文数据已损坏")
//            }
//
//        }
//
//        /**
//         * 公钥解密过程
//         *
//         * @param publicKey     公钥
//         * @param cipherData    密文数据
//         * @return              明文
//         * @throws Exception    解密过程中的异常信息
//         */
//        fun decrypt(publicKey: PublicKey?, cipherData: ByteArray): ByteArray? {
//            if (publicKey == null) throw Exception("解密公钥为空, 请设置")
//            try {
//                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
//                val cipher = Cipher.getInstance(ALGORITHM)
//                // 用密钥初始化此 Cipher 解密模式
//                cipher.init(Cipher.DECRYPT_MODE, publicKey)
//                // 加密或解密数据
//                return cipher.doFinal(cipherData)
//            } catch (e: NoSuchAlgorithmException) {
//                throw Exception("无此解密算法")
//            } catch (e: NoSuchPaddingException) {
//                e.printStackTrace()
//                return null
//            } catch (e: InvalidKeyException) {
//                throw Exception("解密公钥非法,请检查")
//            } catch (e: IllegalBlockSizeException) {
//                throw Exception("密文长度非法")
//            } catch (e: BadPaddingException) {
//                throw Exception("密文数据已损坏")
//            }
//
//        }

        /**
         * 加密过程
         *
         * @param key     秘钥
         * @param plainTextData 明文数据
         * @return 密文
         * @throws Exception 加密过程中的异常信息
         */
        fun encrypt(key: Key?, plainTextData: ByteArray): ByteArray? {
            if (key == null) throw Exception("加密公钥为空, 请设置")
            try {
                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
                val cipher = Cipher.getInstance(ALGORITHM)
                // 用密钥初始化此 Cipher 加密模式
                cipher.init(Cipher.ENCRYPT_MODE, key)
                // 加密或解密数据
                return cipher.doFinal(plainTextData)
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此加密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("加密秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("明文长度非法")
            } catch (e: BadPaddingException) {
                throw Exception("明文数据已损坏")
            }

        }

        /**
         * 解密过程
         *
         * @param key           秘钥
         * @param cipherData    密文数据
         * @return              明文
         * @throws Exception    解密过程中的异常信息
         */
        fun decrypt(key: Key?, cipherData: ByteArray): ByteArray? {
            if (key == null) throw Exception("解密公钥为空, 请设置")
            try {
                // 此类为加密和解密提供密码功能 DES/CBC/PKCS5Padding
                val cipher = Cipher.getInstance(ALGORITHM)
                // 用密钥初始化此 Cipher 解密模式
                cipher.init(Cipher.DECRYPT_MODE, key)
                // 加密或解密数据
                return cipher.doFinal(cipherData)
            } catch (e: NoSuchAlgorithmException) {
                throw Exception("无此解密算法")
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
                return null
            } catch (e: InvalidKeyException) {
                throw Exception("解密秘钥非法,请检查")
            } catch (e: IllegalBlockSizeException) {
                throw Exception("密文长度非法")
            } catch (e: BadPaddingException) {
                throw Exception("密文数据已损坏")
            }

        }

        /**
         * 字节数据转字符串专用集合
         */
        private val HEX_CHAR = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

        /**
         * 字节数据转十六进制字符串
         *
         * @param data  输入数据
         * @return      十六进制内容
         */
        fun byteArrayToString(data: ByteArray): String {
            val stringBuilder = StringBuilder()
            for (i in data.indices) {
                // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
                stringBuilder.append(HEX_CHAR[(data[i].toInt() and 0xf0).ushr(4)])
                // 取出字节的低四位 作为索引得到相应的十六进制标识符
                stringBuilder.append(HEX_CHAR[data[i].toInt() and 0x0f])
                if (i < data.size - 1) stringBuilder.append(' ')
            }
            return stringBuilder.toString()
        }
    }
}