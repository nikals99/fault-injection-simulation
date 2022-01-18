package de.nikals99.ghidrafaultinjector.model;

import java.util.List;

public class SearchForGlitchResponse {
    private String glitchAddress;
    private List<Path> paths;

    public SearchForGlitchResponse() {
    }

    public SearchForGlitchResponse(String glitchAddress, List<Path> paths) {
        this.glitchAddress = glitchAddress;
        this.paths = paths;
    }

    public String getGlitchAddress() {
        return glitchAddress;
    }

    public void setGlitchAddress(String glitchAddress) {
        this.glitchAddress = glitchAddress;
    }

    public List<Path> getPaths() {
        return paths;
    }

    public void setPaths(List<Path> paths) {
        this.paths = paths;
    }

    @Override
    public String toString() {
        return "glitchAddress='" + glitchAddress + "'";
    }
}
