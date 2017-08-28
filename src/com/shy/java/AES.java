package com.shy.java;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AES {
    public static final String ECB = "AES/ECB/PKCS5Padding";
    public static final String CBC = "AES/CBC/PKCS5Padding";
    public static final String ALGORITHM = "AES";

    /**
     * @return 返回随机秘钥
     */
    public static String genKey() {
        try {
            // 返回生成指定算法的秘密密钥的 KeyGenerator 对象。
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            // 确定的密钥大小 128/192/256
            keyGenerator.init(128);
            // 生成一个密钥。 返回基本编码格式的密钥，如果此密钥不支持编码，则返回 null。
            return Base64.encode(keyGenerator.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ECB加密
     *
     * @param data 加密数据
     * @param key  秘钥
     * @return  密文
     */
    public static String ecbEncrypt(String data, String key) throws Exception {
        try {// 1. 传入算法，实例化一个加解密器
            Cipher cipher = Cipher.getInstance(ECB);
            // 2. 传入加密模式和密钥，初始化一个加密器
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(key));
            // 3. 调用doFinal方法加密
            return Base64.encode(cipher.doFinal(data.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("秘钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }
    }

    /**
     * ECB解密
     *
     * @param data 密文数据
     * @param key  秘钥
     * @return      解密数据
     */
    public static String ecbDecrypt(String data, String key) throws Exception {
        try {// 1. 传入算法，实例化一个加解密器
            Cipher cipher = Cipher.getInstance(ECB);
            // 2. 传入解密模式和密钥，初始化一个加密器
            cipher.init(Cipher.DECRYPT_MODE, secretKey(key));
            return new String(cipher.doFinal(Base64.decode(data)));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("秘钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
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
    public static String cbcEncrypt(String data, String key, String iv) throws Exception {
        try {// CBC 模式中的 DES 和使用 OAEP 编码操作的 RSA 密码。
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv(iv));
            Cipher cipher = Cipher.getInstance(CBC);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(key), ivParameterSpec);
            return Base64.encode(cipher.doFinal(data.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("秘钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
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
    public static String cbcDecrypt(String data, String key, String iv) throws Exception {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv(iv));
            Cipher cipher = Cipher.getInstance(CBC);
            cipher.init(Cipher.DECRYPT_MODE, secretKey(key), ivParameterSpec);
            return new String(cipher.doFinal(Base64.decode(data)));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("秘钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 还原密钥
     *
     * @param key
     * @return
     */
    private static SecretKey secretKey(String key) {
        return new SecretKeySpec(Base64.decode(key), ALGORITHM);
    }

    /**
     * 取前16个字节
     * @param iv
     * @return
     */
    private static byte[] iv(String iv) {
        return Arrays.copyOfRange(iv.getBytes(), 0, 16);
    }
}
