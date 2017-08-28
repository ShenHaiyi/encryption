package com.shy.aesrsa;

public class RSA extends CipherKey {
    public static String[] getKey(){
        return getKey(Algorithm.RSA, 1024);
    }

    /**
     * RSA私钥加密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String privateEncrypt(String key, String data) throws Exception {
        return encrypt(Algorithm.RSA.is(true), key, data, null);
    }

    /**
     * RSA公钥解密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String publicDecrypt(String key, String data) throws Exception {
        return decrypt(Algorithm.RSA.is(false), key, data, null);
    }

    /**
     * RSA公钥加密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String publicEncrypt(String key, String data) throws Exception {
        return encrypt(Algorithm.RSA.is(false), key, data, null);
    }

    /**
     * RSA私钥解密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String privateDecrypt(String key, String data) throws Exception {
        return decrypt(Algorithm.RSA.is(true), key, data, null);
    }
}
