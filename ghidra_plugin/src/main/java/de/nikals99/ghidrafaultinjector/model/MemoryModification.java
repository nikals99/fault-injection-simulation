package de.nikals99.ghidrafaultinjector.model;

public class MemoryModification {
    private String address;
    private String value;
    private int length;

    public MemoryModification(String address, String value, int length) {
        this.address = address;
        this.value = value;
        this.length = length;
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

    @Override
    public String toString() {
        return "address='" + address + "'|value='" + value + "'|length=" + length +"'";
    }
}
