package com.shy.aesrsa;

import com.shy.aesrsa.test.Jia;
import com.shy.aesrsa.test.Yi;

public class Test {


    public static void main(String[] args) throws Exception {
        rsa();
        aes();
//        data();
    }

    private static void rsa() throws Exception {
        String[] key = RSA.getKey();
        String data;

        System.out.println("--------------私钥加密公钥解密过程-------------------");
        data = "私钥加密公钥解密过程";
        String encrypt = RSA.privateEncrypt(key[0], data);
        String decrypt = RSA.publicDecrypt(key[1], encrypt);
        System.out.println("原文：" + data);
        System.out.println("密文：" + encrypt);
        System.out.println("解密：" + decrypt);
        System.out.println();

        System.out.println("--------------公钥加密私钥解密过程-------------------");
        data = "公钥加密私钥解密过程";
        encrypt = RSA.publicEncrypt(key[1], data);
        decrypt = RSA.privateDecrypt(key[0], encrypt);
        System.out.println("原文：" + data);
        System.out.println("密文：" + encrypt);
        System.out.println("解密：" + decrypt);
        System.out.println();
    }

    private static void aes() throws Exception {
        String key = AES.getKey();

        System.out.println("--------------AES ECB加密解密过程-------------------");
        String data = "AES ECB加密解密过程";
        String encode =  AES.encrypt(key, data);
        System.out.println("秘钥:" + key);
        System.out.println("原文:" + data);
        System.out.println("加密:" + encode);
        System.out.println("解密:" + AES.decrypt(key, encode));
        System.out.println();

        System.out.println("--------------AES CBC加密解密过程-------------------");
        data = "AES CBC加密解密过程";
        encode = AES.encrypt(key, data, "1234567890123456");
        System.out.println("秘钥:" + key);
        System.out.println("原文:" + data);
        System.out.println("加密:" + encode);
        System.out.println("解密:" + AES.decrypt(key, encode, "1234567890123456"));
        System.out.println();
    }

    public static void data() throws Exception {
        String data = "乙发给甲的数据";
        Jia jia = new Jia();//甲
        Yi yi = new Yi();//乙
        jia.setYiPrivateKey(yi);//甲发送公钥给乙
        yi.getKey(jia, data);//乙把加密的数据发送给甲进行解密
        System.out.println(jia.getData());//甲解密后的数据
    }

}
