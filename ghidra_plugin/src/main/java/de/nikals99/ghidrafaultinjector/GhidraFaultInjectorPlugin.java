package de.nikals99.ghidrafaultinjector;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = "ghidra-faultinjector",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Fault injection analysis from inside ghidra",
        description = "Provides bindings to angr for analysing fault injection attacks"
)
public class GhidraFaultInjectorPlugin extends ProgramPlugin {
    GhidraFaultInjectorProvider provider;
    GhidraFaultInjectorListingContextAction contextAction;

    public GhidraFaultInjectorPlugin(PluginTool tool) {
        super(tool, true, true);
        String pluginName = getName();
        this.provider = new GhidraFaultInjectorProvider(this, pluginName, this.getCurrentProgram());
        this.contextAction = new GhidraFaultInjectorListingContextAction(this, this.getCurrentProgram());
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void programActivated(Program p) {
        provider.setProgram(p);
        contextAction.setProgram(p);
    }
}
