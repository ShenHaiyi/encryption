# encryption
简单的封装了JAVA的RSA和AES加密,RSA和AES最常用的两个加密算法,直接调用加密和解密方法即可。非常简单<br>
## RSA
```java
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
```
## AES
```java
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
```
