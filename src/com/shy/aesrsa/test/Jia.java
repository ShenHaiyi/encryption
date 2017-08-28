package com.shy.aesrsa.test;

import com.shy.aesrsa.AES;
import com.shy.aesrsa.RSA;

public class Jia {

    String privateKey;
    String publicKey;
    String data;

    /**
     * 甲方生成RSE密钥对
     */
    public Jia() {
        String[] key = RSA.getKey();
        privateKey = key[0];
        publicKey = key[1];
    }

    /**
     *  把公钥发给乙方
     * @param yi
     */
    public void setYiPrivateKey(Yi yi){
        yi.setPublicKey(publicKey);
    }

    /**
     *  用乙方提供的加密秘钥和加密数据解密
     */
    public void getDataDecrypt(String encodeKey, String encodeData) throws Exception {
        // 首先用RSA私钥解密AES秘钥
        String key = RSA.privateDecrypt(privateKey, encodeKey);
        // 然后用解密的秘钥解密数据
        data = AES.decrypt(key, encodeData);
    }

    public String getData() {
        return data;
    }
}
