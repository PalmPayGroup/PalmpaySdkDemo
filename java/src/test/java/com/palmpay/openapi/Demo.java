package com.palmpay.openapi;

import org.junit.Assert;
import org.junit.Test;


import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

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

    @Test
    public void test1(){
        int i = 1;
        Integer a = null;
        System.out.println(Objects.equals(i, null));
        System.out.println(Objects.equals(i, 1));
        System.out.println(Objects.equals(null, i));

        Map<String,String> map = new HashMap<>();
        map.put("v1", "v2");
        map.put("v3", "v2");
        System.out.println(map);
        // System.out.println(i == a);
    }


}
