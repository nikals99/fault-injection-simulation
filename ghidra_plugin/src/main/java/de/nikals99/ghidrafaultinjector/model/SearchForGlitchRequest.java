package de.nikals99.ghidrafaultinjector.model;


public class SearchForGlitchRequest {
    private MainOptions mainOptions;
    private FindOptions findOptions;
    private StateModificationOptions stateModificationOptions;
    private GlitchOptions glitchOptions;

    public SearchForGlitchRequest(MainOptions mainOptions, FindOptions findOptions, StateModificationOptions stateModificationOptions, GlitchOptions glitchOptions) {
        this.mainOptions = mainOptions;
        this.findOptions = findOptions;
        this.stateModificationOptions = stateModificationOptions;
        this.glitchOptions = glitchOptions;
    }

    public MainOptions getMainOptions() {
        return mainOptions;
    }

    public void setMainOptions(MainOptions mainOptions) {
        this.mainOptions = mainOptions;
    }

    public FindOptions getFindOptions() {
        return findOptions;
    }

    public void setFindOptions(FindOptions findOptions) {
        this.findOptions = findOptions;
    }

    public StateModificationOptions getStateModificationOptions() {
        return stateModificationOptions;
    }

    public void setStateModificationOptions(StateModificationOptions stateModificationOptions) {
        this.stateModificationOptions = stateModificationOptions;
    }

    public GlitchOptions getGlitchOptions() {
        return glitchOptions;
    }

    public void setGlitchOptions(GlitchOptions glitchOptions) {
        this.glitchOptions = glitchOptions;
    }
}
