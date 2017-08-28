package com.shy.aesrsa.test;

import com.shy.aesrsa.AES;
import com.shy.aesrsa.RSA;

public class Yi {
    String publicKey;


    /**
     * 获取公钥
     * @param publicKey
     */
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * 乙方生成AES秘钥
     * 加密数据
     * 发送给甲方
     */
    public void getKey(Jia jia, String data) throws Exception {
        // 生成AES秘钥
        String key = AES.getKey();
        // 用AES加密数据生成密文
        String encodeData =  AES.encrypt(key, data);
        // 用甲方提供的RSA公钥加密AES秘钥
        String encodeKey =  RSA.publicEncrypt(publicKey, key);
        // 把加密的秘钥和数据发送个甲方
        jia.getDataDecrypt(encodeKey, encodeData);
    }

}
