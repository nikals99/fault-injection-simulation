package de.nikals99.ghidrafaultinjector.model;

public class Instruction {
    private String address;
    private boolean thumb;

    public Instruction(String address, boolean thumb) {
        this.address = address;
        this.thumb = thumb;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public boolean isThumb() {
        return thumb;
    }

    public void setThumb(boolean thumb) {
        this.thumb = thumb;
    }
}
