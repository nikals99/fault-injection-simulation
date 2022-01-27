package de.nikals99.ghidrafaultinjector.model;

public class Instruction {
    private String address;

    public Instruction(String address) {
        this.address = address;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}
