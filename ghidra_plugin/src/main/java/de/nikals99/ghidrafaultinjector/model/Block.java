package de.nikals99.ghidrafaultinjector.model;

import java.util.List;

public class Block {
    private String address;
    private List<String> instructionAddrs;

    public Block() {
    }

    public Block(String address, List<String> instructionAddrs) {
        this.address = address;
        this.instructionAddrs = instructionAddrs;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public List<String> getInstructionAddrs() {
        return instructionAddrs;
    }

    public void setInstructionAddrs(List<String> instructionAddrs) {
        this.instructionAddrs = instructionAddrs;
    }
}
