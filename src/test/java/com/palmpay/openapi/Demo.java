package com.palmpay.openapi;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * @author: yuanpei.liao
 * @date: 2022/12/5
 */

public class Demo {

    @Test
    public void test() throws Exception {
        // 1.生成密钥对
        Map<String, String> keyPair = RsaUtil.generateKeyPair();


        String privateKey = keyPair.get(Constants.PRIVATE_KEY);

        String publicKey = keyPair.get(Constants.PUBLIC_KEY);

        System.out.println("privateKey:");
        System.out.println(privateKey);
        System.out.println("publicKey:");
        System.out.println(publicKey);
        // 2.加签
        Map<String,Object> testData = new HashMap<>(16,1);
        testData.put("bizInfo","{\"key\":\"value\"}");
        testData.put("version","1.1");

        String sign = PalmPayUtil.generateSign(testData, privateKey, SignType.RSA);

        // 3.验签
        boolean result = PalmPayUtil.verifySign(testData, publicKey, sign, SignType.RSA);

        Assert.assertTrue(result);
    }
}
