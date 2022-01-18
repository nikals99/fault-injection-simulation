package de.nikals99.ghidrafaultinjector.model;

import java.util.List;

public class StateModificationOptions {
    private List<MemoryModification> memoryModifications;

    public StateModificationOptions(List<MemoryModification> memoryModifications) {
        this.memoryModifications = memoryModifications;
    }

    public List<MemoryModification> getMemoryModifications() {
        return memoryModifications;
    }

    public void setMemoryModifications(List<MemoryModification> memoryModifications) {
        this.memoryModifications = memoryModifications;
    }
}
