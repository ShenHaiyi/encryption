package com.shy.java;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Test {
    public static void main(String[] args) throws Exception {
        rsa();
        aes();
    }

    public static void rsa() throws Exception {
        String[] keyPairGen = RSAEncrypt.genKeyPair();
        PrivateKey privateKey = RSAEncrypt.strToPrivateKey(keyPairGen[0]);
        PublicKey publicKey = RSAEncrypt.strToPublicKey(keyPairGen[1]);
        String data;

        System.out.println("--------------私钥加密公钥解密过程-------------------");
        data = "私钥加密公钥解密过程";
        byte[] encrypt = RSAEncrypt.encrypt(privateKey, data.getBytes());
        byte[] decrypt = RSAEncrypt.decrypt(publicKey, encrypt);
        System.out.println("原文：" + data);
        System.out.println("密文：" + Base64.encode(encrypt));
        System.out.println("解密：" + new String(decrypt));
        System.out.println();

        System.out.println("--------------公钥加密私钥解密过程-------------------");
        data = "公钥加密私钥解密过程";
        encrypt = RSAEncrypt.encrypt(publicKey, data.getBytes());
        decrypt = RSAEncrypt.decrypt(privateKey, encrypt);
        System.out.println("原文：" + data);
        System.out.println("密文：" + Base64.encode(encrypt));
        System.out.println("解密：" + new String(decrypt));
        System.out.println();

        System.out.println("--------------私钥签名公钥验签过程-------------------");
        data = "私钥签名公钥验签过程";
        String sign = RSASignature.sign(data, keyPairGen[0], null);
        System.out.println("原文：" + data);
        System.out.println("签名串：" + sign);
        System.out.println("验签结果：" + RSASignature.doCheck(data, sign, keyPairGen[1], null));
        System.out.println();
    }

    public static void aes() throws Exception {
        String key = AES.genKey();//生成秘钥

        System.out.println("--------------AES ECB加密解密过程-------------------");
        String data = "AES ECB加密解密过程";
        String encode = AES.ecbEncrypt(data, key);
        System.out.println("秘钥:" + key);
        System.out.println("原文:" + data);
        System.out.println("加密:" + encode);
        System.out.println("解密:" + AES.ecbDecrypt(encode, key));
        System.out.println();

        System.out.println("--------------AES CBC加密解密过程-------------------");
        data = "AES CBC加密解密过程";
        encode = AES.cbcEncrypt(data, key, "这里只取前16个字节");
        System.out.println("秘钥:" + key);
        System.out.println("原文:" + data);
        System.out.println("加密:" + encode);
        System.out.println("解密:" + AES.cbcDecrypt(encode, key, "这里只取前16个字节"));
        System.out.println();
    }

}
