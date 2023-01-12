package com.palmpay.openapi;

/**
 * @author: yuanpei.liao
 * @date: 2022/12/14
 */
public enum AccountTypeEnum {
    BALANCE_ACC(1,"个人余额账户"),
    PROVISIONS_ACC(2,"备付金账户"),
    MIDDLE_ACC(3,"中间户"),
    MERCHANT_ACC(4,"商家账户"),
    LINKED_ACC(5,"关联账户"),
    BANK_ACC(6,"银行账户"),
    ;

    private int value;

    private String desc;

    public int getValue() {
        return value;
    }

    private AccountTypeEnum(int value, String desc) {
        this.value = value;
        this.desc = desc;
    }


    public void setValue(int value) {
        this.value = value;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }
}
