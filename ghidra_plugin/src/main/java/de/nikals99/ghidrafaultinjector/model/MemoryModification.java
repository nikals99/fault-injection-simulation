package de.nikals99.ghidrafaultinjector.model;

public class MemoryModification {
    private String address;
    private String value;
    private int length;
    private String byteOrdering;

    public MemoryModification(String address, String value, int length, String byteOrdering) {
        this.address = address;
        this.value = value;
        this.length = length;
        this.byteOrdering = byteOrdering;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public String getByteOrdering() {
        return byteOrdering;
    }

    public void setByteOrdering(String byteOrdering) {
        this.byteOrdering = byteOrdering;
    }

    @Override
    public String toString() {
        return "address='" + address + "'|value='" + value + "'|length=" + length +"'|byteorder='" + byteOrdering + "'";
    }
}
