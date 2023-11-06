package com.palmpay.openapi;


import com.alibaba.fastjson.JSON;

import java.net.URLDecoder;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;

public class PalmPayUtil {
	
	private static final String SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final Random RANDOM = new SecureRandom();

	/**
	 * 商户请求PalmPay时需要参与RSA签名的字段
	 */
    private static final List<String> MERCHANTNEEDSIGNFILED = Arrays.asList(Constants.REQUESTTIME,Constants.VERSION,Constants.NONCESTR,Constants.BIZINFO);

	/**
	 * 其他场景需要参与签名的字段
	 */
    private static final List<String> OTHERSNEEDSIGNFILED = Arrays.asList();
    
    /**
     * 获取当前时间戳
     * @return 时间戳
     */
    public static String generateTimestamp(){
    	Timestamp now = Timestamp.valueOf(LocalDateTime.now());
    	return String.valueOf(now.getTime());
    }

	/**
     * 获取随机字符串 Nonce Str
     *
     * @return String 随机字符串
     */
    public static String generateNonceStr() {
        char[] nonceChars = new char[32];
        for (int index = 0; index < nonceChars.length; ++index) {
            nonceChars[index] = SYMBOLS.charAt(RANDOM.nextInt(SYMBOLS.length()));
        }
        return new String(nonceChars);
    }
    
	/**
	 * 生成签名
	 * @param data Map<String, Object> 
	 * @param privateKey base64编码的私钥
	 * @param signType 商户使用:SignType.RSA
	 * @return
	 * @throws Exception
	 */
    public static String generateSign(final Map<String, Object> data,String privateKey,SignType signType) throws Exception {
    	Map<String, String> map = new HashMap<>();
    	Set<String> set = data.keySet();
    	if(SignType.RSA.equals(signType)){
    		for (String key : set) {
    			if(MERCHANTNEEDSIGNFILED.contains(key)){
    				map.put(key,String.valueOf(data.get(key)));
    			}
    		}
    	}else{
    		for (String key : set) {
    			if(OTHERSNEEDSIGNFILED.contains(key)){
    				map.put(key,String.valueOf(data.get(key)));
    			}
    		}
    	}
        return generateSignature(map, privateKey,signType);
   }
	
    /**
     * 验证签名
     * @param data  Map<String, Object>
     * @param publicKey base64编码的公钥
     * @param sign
	 * @param signType 商户使用:SignType.RSA
     * @return
     * @throws Exception
     */
    public static boolean verifySign(final Map<String, Object> data,String publicKey,String sign,SignType signType) throws Exception{
    	Map<String, String> map = new HashMap<>();
    	Set<String> set = data.keySet();
    	if(SignType.RSA.equals(signType)){
    		for (String key : set) {
    			if(MERCHANTNEEDSIGNFILED.contains(key)){
    				map.put(key,String.valueOf(data.get(key)));
    			}
    		}
    	}else{
    		for (String key : set) {
    			if(OTHERSNEEDSIGNFILED.contains(key)){
    				map.put(key,String.valueOf(data.get(key)));
    			}
    		}
    	}
    	return verifySignature(map, publicKey, sign, signType);
    }

	/**
	 * 回调接口验签逻辑
	 * @param publicKey PalmPay平台公钥，不是商户自己生成的公钥
	 * @return
	 */
	public static boolean verifySignForCallback(String paramBodyJson,String publicKey,SignType signType) throws Exception {
		Map<String, String> data = JSON.parseObject(paramBodyJson, Map.class);
		Set<String> set = data.keySet();
		if(SignType.RSA.equals(signType)){
			for (String key : set) {
				data.put(key,String.valueOf(data.get(key)));
			}
		}
		String sign = data.get("sign");
		sign =  URLDecoder.decode(sign,"UTF-8");
		data.remove("sign");
		return verifySignature(data,publicKey,sign,signType);
	}
    
	/**
	 * 生成签名
	 * @param data Map<String, String>
	 * @param privateKey base64编码的私钥
	 * @param signType SignType.RSA or SignType.HMACSHA256
	 * @return
	 * @throws Exception
	 */
    private static String generateSignature(final Map<String, String> data, String privateKey,SignType signType) throws Exception {
         String encryData = sortStr(data);
         if(SignType.RSA.equals(signType)){
        	 return RsaUtil.sign(encryData, privateKey);
         }else{
        	 return RsaUtil.HMACSHA256(encryData, privateKey);
         }
    }

    /**
     * 验证签名
     * @param data Map<String, String>
     * @param publicKey base64编码的公钥
     * @param sign 
     * @param signType SignType.RSA or SignType.HMACSHA256
     * @return
     * @throws Exception
     */
    private static boolean verifySignature(final Map<String, String> data,String publicKey,String sign,SignType signType) throws Exception{
    	String encryData = sortStr(data);
    	if(SignType.RSA.equals(signType)){
    		return RsaUtil.verify(encryData, publicKey, sign);
    	}else{
    		return RsaUtil.HMACSHA256(encryData, publicKey).equals(sign);
    	}
    }
    
    private static String sortStr(final Map<String, String> data) throws Exception{
    	Set<String> keySet = data.keySet();
        String[] keyArray = keySet.toArray(new String[keySet.size()]);
        Arrays.sort(keyArray);
        StringBuilder sb = new StringBuilder();
        for (String k : keyArray) {
            if (data.get(k).trim().length() > 0) // 参数值为空，则不参与签名
                sb.append(k).append("=").append(data.get(k).trim()).append("&");
        }
       return Md5Util.MD5(sb.substring(0, sb.length()-1));
    }
    
}
