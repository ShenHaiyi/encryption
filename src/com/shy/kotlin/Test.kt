package com.shy.kotlin

fun main(args: Array<String>) {
    rsa()
    aes()
}

fun rsa(){
    val keyPairGen = RSAEncrypt.genKeyPair()
    val privateKey = RSAEncrypt.strToPrivateKey(keyPairGen!![0])
    val publicKey = RSAEncrypt.strToPublicKey(keyPairGen[1])

    println("--------------私钥加密公钥解密过程-------------------")
    var data = "私钥加密公钥解密过程"
    var encrypt = RSAEncrypt.encrypt(privateKey, data.toByteArray())
    var decrypt = RSAEncrypt.decrypt(publicKey, encrypt!!)
    println("原文：$data")
    println("密文：${Base64.encode(encrypt)}")
    println("解密：${String(decrypt!!)}")
    println()

    println("--------------公钥加密私钥解密过程-------------------")
    data = "公钥加密私钥解密过程"
    encrypt = RSAEncrypt.encrypt(publicKey, data.toByteArray())
    decrypt = RSAEncrypt.decrypt(privateKey, encrypt!!)
    println("原文：$data")
    println("密文：${Base64.encode(encrypt)}")
    println("解密：${String(decrypt!!)}")
    println()

    println("--------------私钥签名公钥验签过程-------------------")
    data = "私钥签名公钥验签过程"
    var sign = RSASignature.sign(data, keyPairGen[0])
    println("原文：$data")
    println("签名串：$sign")
    println("验签结果：${RSASignature.doCheck(data, sign!!, keyPairGen[1])}")
    println()
}

fun aes(){
    val key = AES.genKey()//生成秘钥

    println("--------------AES ECB加密解密过程-------------------")
    var data = "AES ECB加密解密过程"
    var encode = AES.ecbEncrypt(data, key!!)
    println("原文:" + data)
    println("密文:" + encode!!)
    println("解密:" + AES.ecbDecrypt(encode, key)!!)
    println()

    println("--------------AES CBC加密解密过程-------------------")
    data = "AES ECB加密解密过程"
    encode = AES.cbcEncrypt(data, key, "这里只取前16个字节")
    println("原文:" + data)
    println("密文:" + encode!!)
    println("解密:" + AES.cbcDecrypt(encode, key, "这里只取前16个字节")!!)
    println()
}