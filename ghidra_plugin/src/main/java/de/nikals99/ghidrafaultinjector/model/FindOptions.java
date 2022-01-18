package de.nikals99.ghidrafaultinjector.model;

public class FindOptions {
    private String findAddress;
    private String[] avoidAddresses;
    private boolean useCustomFindFunction;
    private String customFindFunction;

    public FindOptions(String findAddress, String[] avoidAddresses, boolean useCustomFindFunction, String blankStateStartAtAddress) {
        this.findAddress = findAddress;
        this.avoidAddresses = avoidAddresses;
        this.useCustomFindFunction = useCustomFindFunction;
        this.customFindFunction = blankStateStartAtAddress;
    }

    public String getFindAddress() {
        return findAddress;
    }

    public void setFindAddress(String findAddress) {
        this.findAddress = findAddress;
    }

    public String[] getAvoidAddresses() {
        return avoidAddresses;
    }

    public void setAvoidAddresses(String[] avoidAddresses) {
        this.avoidAddresses = avoidAddresses;
    }

    public boolean isUseCustomFindFunction() {
        return useCustomFindFunction;
    }

    public void setUseCustomFindFunction(boolean useCustomFindFunction) {
        this.useCustomFindFunction = useCustomFindFunction;
    }

    public String getCustomFindFunction() {
        return customFindFunction;
    }

    public void setCustomFindFunction(String customFindFunction) {
        this.customFindFunction = customFindFunction;
    }
}
