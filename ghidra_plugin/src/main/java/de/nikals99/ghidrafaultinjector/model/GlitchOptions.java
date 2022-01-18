package de.nikals99.ghidrafaultinjector.model;

import java.util.List;

public class GlitchOptions {
    private List<Instruction> instructions;

    public GlitchOptions(List<Instruction> instructions) {
        this.instructions = instructions;
    }

    public List<Instruction> getInstructions() {
        return instructions;
    }

    public void setInstructions(List<Instruction> instructions) {
        this.instructions = instructions;
    }
}
