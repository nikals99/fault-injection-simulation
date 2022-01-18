package de.nikals99.ghidrafaultinjector.model;

public class MainOptions {
    private String pathToBinary;
    private String angrBackend;
    private String arch;
    private String entryPoint;
    private String baseAddress;
    private boolean useBlankState;
    private String blankStateStartAt;

    public MainOptions(String pathToBinary, String angrBackend, String arch, String entryPoint, String baseAddress, boolean useBlankState, String blankStateStartAt) {
        this.pathToBinary = pathToBinary;
        this.angrBackend = angrBackend;
        this.arch = arch;
        this.entryPoint = entryPoint;
        this.baseAddress = baseAddress;
        this.useBlankState = useBlankState;
        this.blankStateStartAt = blankStateStartAt;
    }

    public String getPathToBinary() {
        return pathToBinary;
    }

    public void setPathToBinary(String pathToBinary) {
        this.pathToBinary = pathToBinary;
    }

    public String getAngrBackend() {
        return angrBackend;
    }

    public void setAngrBackend(String angrBackend) {
        this.angrBackend = angrBackend;
    }

    public String getArch() {
        return arch;
    }

    public void setArch(String arch) {
        this.arch = arch;
    }

    public String getEntryPoint() {
        return entryPoint;
    }

    public void setEntryPoint(String entryPoint) {
        this.entryPoint = entryPoint;
    }

    public String getBaseAddress() {
        return baseAddress;
    }

    public void setBaseAddress(String baseAddress) {
        this.baseAddress = baseAddress;
    }

    public boolean isUseBlankState() {
        return useBlankState;
    }

    public void setUseBlankState(boolean useBlankState) {
        this.useBlankState = useBlankState;
    }

    public String getBlankStateStartAt() {
        return blankStateStartAt;
    }

    public void setBlankStateStartAt(String blankStateStartAt) {
        this.blankStateStartAt = blankStateStartAt;
    }
}
