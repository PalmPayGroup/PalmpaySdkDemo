package com.palmpay.openapi;

import java.security.MessageDigest;

public class Md5Util {
	
	/**
	 * 生成MD5（转换成大写字母）
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String MD5(String data) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] array = md.digest(data.getBytes("UTF-8"));
		StringBuilder sb = new StringBuilder();
		for (byte item : array) {
			sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
		}
		return sb.toString().toUpperCase();
	}
	
}
