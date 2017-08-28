package com.shy.aesrsa;

import com.shy.java.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class CipherKey {
    /**
     * @param algorithm 算法
     * @param keysize   秘钥长度
     * @return 秘钥
     */
    public static String[] getKey(Algorithm algorithm, int keysize) {
        try {
            String alg = algorithm.toString();
            switch (algorithm) {
                case AES:
                    KeyGenerator keyGenerator = KeyGenerator.getInstance(alg);
                    keyGenerator.init(keysize);// 128/192/256
                    return new String[]{Base64.encode(keyGenerator.generateKey().getEncoded())};

                case RSA:
                    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(alg);
                    keyPairGen.initialize(keysize, new SecureRandom());
                    KeyPair keyPair = keyPairGen.generateKeyPair();
                    return new String[]{Base64.encode(keyPair.getPrivate().getEncoded()),
                            Base64.encode(keyPair.getPublic().getEncoded())};
                default:
                    return null;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 加密
     *
     * @param algorithm 算法
     * @param key       秘钥
     * @param data      数据
     * @param iv        参数
     * @return
     * @throws Exception
     */
    public static String encrypt(Algorithm algorithm, String key, String data, String iv) throws Exception {
        return doFinal(Cipher.ENCRYPT_MODE, algorithm, key, data, iv);
    }

    /**
     * 解密
     *
     * @param algorithm 算法
     * @param key       秘钥
     * @param data      数据
     * @param iv        参数
     * @return
     * @throws Exception
     */
    public static String decrypt(Algorithm algorithm, String key, String data, String iv) throws Exception {
        return doFinal(Cipher.DECRYPT_MODE, algorithm, key, data, iv);
    }

    /**
     * @param opmode    Cipher的操作模式
     *                  ENCRYPT_MODE 加密模式、
     *                  DECRYPT_MODE 解密模式、
     *                  WRAP_MODE 密钥包装模式、
     *                  UNWRAP_MODE 密钥解包模式
     * @param algorithm 算法
     * @param key       秘钥
     * @param data      数据
     * @param iv        参数
     * @return
     * @throws Exception
     */
    public static String doFinal(int opmode, Algorithm algorithm, String key, String data, String iv) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.toString());
            String alg = algorithm.toString();
            boolean is = algorithm.is;
            byte[] buffer = Base64.decode(key);
            switch (algorithm) {
                case AES:
                    Key aesKey = new SecretKeySpec(buffer, alg);
                    if (is) cipher.init(opmode, aesKey);
                    else{
                        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(opmode, aesKey, new IvParameterSpec(
                                Arrays.copyOfRange(iv.getBytes(), 0, 16)));
                    }
                    break;
                case RSA:
                    KeyFactory keyFactory = KeyFactory.getInstance(alg); Key rsaKey;
                    if (is) rsaKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(buffer));
                    else rsaKey = keyFactory.generatePublic(new X509EncodedKeySpec(buffer));
                    cipher.init(opmode, rsaKey);
                    break;
            }
            switch (opmode) {
                case Cipher.ENCRYPT_MODE:
                    return Base64.encode(cipher.doFinal(data.getBytes()));
                case Cipher.DECRYPT_MODE:
                    return new String(cipher.doFinal(Base64.decode(data)));
                default:
                    return null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("秘钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("数据长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("数据已损坏");
        } catch (InvalidKeySpecException e) {
            throw new Exception("秘钥非法");
        } catch (NullPointerException e) {
            throw new Exception("秘钥数据为空");
        }
    }

}
