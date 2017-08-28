package com.shy.aesrsa;

public class AES extends CipherKey {
    /**
     * @return  获取AES秘钥
     */
    public static String getKey(){
        return getKey(Algorithm.AES, 128)[0];
    }

    /**
     * AES ECB加密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String encrypt(String key, String data) throws Exception {
        return encrypt(Algorithm.AES.is(true), key, data, null);
    }

    /**
     * AES ECB解密
     *
     * @param key       秘钥
     * @param data      数据
     * @return
     * @throws Exception
     */
    public static String decrypt(String key, String data) throws Exception {
        return decrypt(Algorithm.AES.is(true), key, data, null);
    }

    /**
     * AES CBC加密
     *
     * @param key       秘钥
     * @param data      数据
     * @param iv        参数
     * @return
     * @throws Exception
     */
    public static String encrypt(String key, String data, String iv) throws Exception {
        return encrypt(Algorithm.AES.is(false), key, data, iv);
    }

    /**
     * AES CBC解密
     *
     * @param key       秘钥
     * @param data      数据
     * @param iv        参数
     * @return
     * @throws Exception
     */
    public static String decrypt(String key, String data, String iv) throws Exception {
        return decrypt(Algorithm.AES.is(false), key, data, iv);
    }
}
