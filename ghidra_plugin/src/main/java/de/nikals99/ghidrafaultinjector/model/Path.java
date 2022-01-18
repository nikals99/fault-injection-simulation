package de.nikals99.ghidrafaultinjector.model;

import java.util.List;

public class Path {
    private List<Block> blocks;
    private int instructionCount;

    public Path() {
    }

    public Path(List<Block> blocks) {
        this.blocks = blocks;
    }

    public List<Block> getBlocks() {
        return blocks;
    }

    public void setBlocks(List<Block> blocks) {
        this.blocks = blocks;
    }

    public int getInstructionCount() {
        return instructionCount;
    }

    public void setInstructionCount(int instructionCount) {
        this.instructionCount = instructionCount;
    }

    @Override
    public String toString() {
        return "numberOfBlocks='" + blocks.size() + "'|numberOfInstructions='" + instructionCount + "'";
    }
}
