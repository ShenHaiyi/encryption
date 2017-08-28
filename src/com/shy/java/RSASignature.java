package com.shy.java;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA签名验签类
 */
public class RSASignature {
    /**
     * 签名算法
     *
     * MD2withRSA / MD5withRSA / SHA1withRSA
     */
    public static final String ALGORITHM = "SHA1WithRSA";

    /**
     * RSA签名
     *
     * @param content    待签名数据
     * @param privateKey 私钥
     * @param encode     字符集编码
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String encode) {
        try {// 根据给定的编码密钥创建一个新的 PKCS8EncodedKeySpec。
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            // 返回转换指定算法的 public/private 关键字的 KeyFactory 对象。
            KeyFactory keyf = KeyFactory.getInstance(RSAEncrypt.ALGORITHM);
            // 根据提供的密钥规范（密钥材料）生成私钥对象。
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            // 返回实现指定签名算法的 Signature 对象。MD2withRSA / MD5withRSA / SHA1withRSA
            Signature signature = Signature.getInstance(ALGORITHM);
            // 初始化这个用于签名的对象。
            signature.initSign(priKey);
            // 从指定的偏移量开始，使用指定的 byte 数组更新要签名或验证的数据。
            signature.update(content.getBytes(encode == null ? Charset.defaultCharset().name() : encode));
            // 返回所有已更新数据的签名字节。
            return Base64.encode(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * RSA验签名检查
     *
     * @param content   待签名数据
     * @param sign      签名值
     * @param publicKey 分配给开发商公钥
     * @param encode    字符集编码
     * @return 布尔值
     */
    public static boolean doCheck(String content, String sign, String publicKey, String encode) {
        try {// 返回转换指定算法的 public/private 关键字的 KeyFactory 对象。
            KeyFactory keyFactory = KeyFactory.getInstance(RSAEncrypt.ALGORITHM);

            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));
            // 返回实现指定签名算法的 Signature 对象。MD2withRSA / MD5withRSA / SHA1withRSA
            Signature signature = Signature.getInstance(ALGORITHM);
            // 初始化此用于验证的对象。
            signature.initVerify(pubKey);
            // 从指定的偏移量开始，使用指定的 byte 数组更新要签名或验证的数据。
            signature.update(content.getBytes(encode == null ? Charset.defaultCharset().name() : encode));
            // 验证传入的签名。
            return signature.verify(Base64.decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
