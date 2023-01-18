package com.palmpay.openapi;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class RsaUtil {

	/**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

    /**
     * RSA加密模式
     */
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";


    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    private static final int KEY_SIZE = 1024;
	
    /**
     * 生成秘钥对
     * 公钥需上传至PalmPay商户平台
     * 私钥商户自己保存
     * @return
     * @throws Exception
     */
    public static Map<String, String> generateKeyPair() throws Exception {
        return generateKeyPair(UUID.randomUUID().toString());
    }
    
    /**
     * 生成秘钥对
     * 公钥需上传至PalmPay商户平台
     * 私钥商户自己保存 
     * @param seed 随机字符串
     * @return
     * @throws Exception
     */
    public static Map<String, String> generateKeyPair(String seed) throws Exception {
    	SecureRandom secureRandom = new SecureRandom(seed.getBytes()); 
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEY_SIZE,secureRandom);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, String> keyMap = new HashMap<String, String>(2);
        keyMap.put(Constants.PUBLIC_KEY, Base64Util.encode(publicKey.getEncoded()));
        keyMap.put(Constants.PRIVATE_KEY, Base64Util.encode(privateKey.getEncoded()));
        return keyMap;
    }
    
    /**
     * base64字符串转换为公钥
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] keyBytes = Base64Util.decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey pubkey = keyFactory.generatePublic(keySpec);
        return pubkey;
    }
    
    /**
     * base64字符串转换为私钥
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        byte[] keyBytes = Base64Util.decode(privateKey.getBytes());
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        return privateK;
    }
    
    /**
     * 读取文件获取base64字符串
     * @param path
     * @return
     * @throws Exception
     */
    private static String readPemFile(String path) throws Exception {
        BufferedReader br = null;
        StringBuilder sb = new StringBuilder();
        try {
            br = new BufferedReader(new FileReader(path));
            String s = "";
            while ((s = br.readLine()) != null) {
                if ((s.charAt(0)) == '-') {
                    continue;
                }
                sb.append(s);
                sb.append("\r");
            }
        } finally {
            if (br != null) {
                br.close();
            }
        }
        return sb.toString();
    }
    
    /**
     * 读取文件获取公钥
     * @param path
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKeyByFile(String path) throws Exception {
        return getPublicKey(readPemFile(path));
    }

    /**
     * 读取文件获取私钥
     * @param path
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKeyByFile(String path) throws Exception {
        return getPrivateKey(readPemFile(path));
    }
    
    /**
     * 公钥加密 (Base64编码)
     * @param srcData
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String srcData, String publicKey) throws Exception {
        PublicKey publicK = getPublicKey(publicKey);
        byte[] data = srcData.getBytes("UTF-8");
        // 对数据加密
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        byte[] base64bytes = Base64Util.decode(encryptedData);
        return new String(base64bytes);
    }
    
    /**
     * 私钥解密
     * @param encryptedData
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        PrivateKey prikey = getPrivateKey(privateKey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(2, prikey);
        byte[] deBytes = cipher.doFinal(encryptedData);
        return deBytes;
    }
    
    /**
     * 签名
     * @param encryData   参与签名字段
     * @param privateKey  私钥（Base64编码）
     * @return
     * @throws Exception
     */
    public static String sign(String encryData, String privateKey) throws Exception {
        byte[] data = encryData.getBytes();
        PrivateKey privateK = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64Util.encode(signature.sign());
    }
    
    /**
     * 验证签名
     * @param encryData   参与签名字段
     * @param publicKey   公钥(BASE64编码)
     * @param sign        数字签名
     * @return
     * @throws Exception
     */
    public static boolean verify(String encryData, String publicKey, String sign) throws Exception {
        byte[] data = encryData.getBytes();
        PublicKey publicK = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        byte[] bsign = Base64Util.decode(sign.getBytes());
        return signature.verify(bsign);
    }
    
    /**
     * 生成 HMACSHA256
     * @param data 待处理数据
     * @param key 密钥
     * @return 加密结果
     * @throws Exception
     */
    public static String HMACSHA256(String data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] array = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte item : array) {
            sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
        }
        return sb.toString().toUpperCase();
    }
    
}
