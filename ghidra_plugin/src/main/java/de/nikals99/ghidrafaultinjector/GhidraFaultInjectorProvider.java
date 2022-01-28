package de.nikals99.ghidrafaultinjector;

import de.nikals99.ghidrafaultinjector.panels.*;
import de.nikals99.ghidrafaultinjector.model.SearchForGlitchRequest;
import de.nikals99.ghidrafaultinjector.tasks.FindGlitchTask;
import docking.ComponentProvider;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.VariableHeightPairLayout;
import ghidra.util.task.TaskLauncher;

import javax.swing.*;

public class GhidraFaultInjectorProvider extends ComponentProvider {
    private JPanel panel;
    MainOptionsPanel mainOptionsPanel;
    FindOptionsPanel findOptionsPanel;
    StateModificationOptionsPanel stateModificationOptionsPanel;
    GlitchOptionsPanel glitchOptionsPanel;
    SearchForGlitchResponsePanel searchForGlitchResponsePanel;
    private Program program;
    private ColorizingService colorizingService;
    private Plugin plugin;


    public GhidraFaultInjectorProvider(Plugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        this.program = program;
        this.plugin = plugin;

        // build the main plugin panel
        buildPanel();
    }

    public void buildPanel() {
        // create the main panel
        panel = new JPanel();
        // add a tabbed pane to the main panel
        JTabbedPane tabPane = new JTabbedPane();
        panel.add(tabPane);

        // set up the first tab of the tab pane
        JPanel searchForGlitchPanel = new JPanel();
        // use a layout with two columns
        searchForGlitchPanel.setLayout(new VariableHeightPairLayout());

        // create the main options panel and add it to the tab
        mainOptionsPanel = new MainOptionsPanel(this.program);
        searchForGlitchPanel.add(mainOptionsPanel);

        // create the find options panel and add it to the tab
        findOptionsPanel = new FindOptionsPanel();
        searchForGlitchPanel.add(findOptionsPanel);

        // create the state modification panel and add it to the tab
        stateModificationOptionsPanel = new StateModificationOptionsPanel();
        searchForGlitchPanel.add(stateModificationOptionsPanel);

        // create the glitch options panel and add it to the tab
        glitchOptionsPanel = new GlitchOptionsPanel(this);
        searchForGlitchPanel.add(glitchOptionsPanel);

        // add the first tab to the tab pane
        tabPane.addTab("SearchForGlitch", searchForGlitchPanel);

        // create the second tab and add it to the tab pane
        searchForGlitchResponsePanel = new SearchForGlitchResponsePanel(this.program, this.colorizingService);
        tabPane.addTab("Response", searchForGlitchResponsePanel);

        // make the window visible
        setVisible(true);
    }

    // this function is used by the glitchoptions panel to collect input from the other panels and send them to python
    public void sendRequestToPython() {
        // collect the information
        SearchForGlitchRequest req = new SearchForGlitchRequest(
                mainOptionsPanel.getMainOptions(),
                findOptionsPanel.getFindOptions(),
                stateModificationOptionsPanel.getStateModificationOptions(),
                glitchOptionsPanel.getGlitchOptions()
        );
        // launch a Task that executes angr
        TaskLauncher.launch(new FindGlitchTask(plugin, req, searchForGlitchResponsePanel));
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program program) {
        // if the loaded program / binary changes: update all references to it
        this.program = program;
        this.searchForGlitchResponsePanel.setProgram(program);
        this.mainOptionsPanel.setProgram(program);

        // create a new instance of colorizingService and update all references to it
        ColorizingService colorizingService = plugin.getTool().getService(ColorizingService.class);
        if (colorizingService == null) {
            System.out.println("Can't find ColorizingService");
        }
        this.colorizingService = colorizingService;
        this.searchForGlitchResponsePanel.setColorizingService(colorizingService);
    }
}
