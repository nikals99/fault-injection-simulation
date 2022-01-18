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
import javax.swing.border.TitledBorder;
import java.awt.*;

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
        ColorizingService colorizingService = plugin.getTool().getService(ColorizingService.class);
        if (colorizingService == null) {
            System.out.println("Can't find ColorizingService service");
        }
        this.colorizingService = colorizingService;
        buildPanel();
        System.out.println(plugin.getName());

    }

    public void buildPanel() {
        panel = new JPanel();
        JTabbedPane tabPane = new JTabbedPane();
        panel.add(tabPane);

        JPanel searchForGlitchPanel = new JPanel();
        searchForGlitchPanel.setLayout(new VariableHeightPairLayout());
        mainOptionsPanel = new MainOptionsPanel(this.program);
        searchForGlitchPanel.add(mainOptionsPanel);

        findOptionsPanel = new FindOptionsPanel();
        searchForGlitchPanel.add(findOptionsPanel);

        stateModificationOptionsPanel = new StateModificationOptionsPanel();
        searchForGlitchPanel.add(stateModificationOptionsPanel);

        searchForGlitchPanel.add(buildFindGlitchSection());
        tabPane.addTab("SearchForGlitch", searchForGlitchPanel);

        searchForGlitchResponsePanel = new SearchForGlitchResponsePanel(this.program, this.colorizingService);
        tabPane.addTab("Response", searchForGlitchResponsePanel);
        setVisible(true);
    }

    private Component buildFindGlitchSection() {
        JPanel findGlichtPanel = new JPanel();
        findGlichtPanel.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find Glitch");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        findGlichtPanel.setBorder(borderMPO);
        findGlichtPanel.setLayout(new BorderLayout());

        glitchOptionsPanel = new GlitchOptionsPanel();
        findGlichtPanel.add(glitchOptionsPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        JButton runButton = new JButton("RUN");
        runButton.addActionListener(actionListener -> {
            SearchForGlitchRequest req = new SearchForGlitchRequest(
                    mainOptionsPanel.getMainOptions(),
                    findOptionsPanel.getFindOptions(),
                    stateModificationOptionsPanel.getStateModificationOptions(),
                    glitchOptionsPanel.getGlitchOptions()
            );

            TaskLauncher.launch(new FindGlitchTask(plugin, req, searchForGlitchResponsePanel));
        });
        buttonPanel.add(runButton);

        findGlichtPanel.add(buttonPanel, BorderLayout.SOUTH);

        return findGlichtPanel;
    }


    //TODO early return (when first path is found)

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program program) {
        this.program = program;
        ColorizingService colorizingService = plugin.getTool().getService(ColorizingService.class);
        if (colorizingService == null) {
            System.out.println("Can't find ColorizingService service");
        }
        this.colorizingService = colorizingService;
        this.searchForGlitchResponsePanel.setProgram(program);
        this.searchForGlitchResponsePanel.setColorizingService(colorizingService);
        this.mainOptionsPanel.setProgram(program);
    }
}
