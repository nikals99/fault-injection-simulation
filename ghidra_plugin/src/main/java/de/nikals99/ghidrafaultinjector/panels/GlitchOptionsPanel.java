package de.nikals99.ghidrafaultinjector.panels;

import de.nikals99.ghidrafaultinjector.GhidraFaultInjectorProvider;
import de.nikals99.ghidrafaultinjector.model.Instruction;
import de.nikals99.ghidrafaultinjector.model.GlitchOptions;
import docking.widgets.ScrollableTextArea;
import docking.widgets.label.GLabel;
import ghidra.util.layout.VariableHeightPairLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;

public class GlitchOptionsPanel extends JPanel {
    private ScrollableTextArea glitchAddresses;
    GhidraFaultInjectorProvider provider;

    public GlitchOptionsPanel(GhidraFaultInjectorProvider provider) {
        super();
        this.provider = provider;
        buildFindGlitchOuterSection();
    }

    private Component buildGlitchOptionsPanel() {
        // create a new panel
        JPanel panel = new JPanel();
        // add a border to the panel
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Glitch options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.setBorder(borderMPO);

        // use a ghidra layout that supports label -> input pairs
        panel.setLayout(new VariableHeightPairLayout());

        // add a textArea + label for adding glitchAddresses
        glitchAddresses = new ScrollableTextArea(5, 25);
        JScrollPane glitchAddrsScrollPane = new JScrollPane(glitchAddresses);
        panel.add(new GLabel("Glitch addresses:", SwingConstants.RIGHT));
        panel.add(glitchAddrsScrollPane);

        return panel;
    }

    public GlitchOptions getGlitchOptions() {
        String[] instructionAddrs = glitchAddresses.getText().split("\n");
        ArrayList<Instruction> instructions = new ArrayList<>();

        // Convert from string to instruction
        for (String instructionAddr : instructionAddrs) {
            instructions.add(new Instruction(instructionAddr));
        }
        // convert to glitch options object
        GlitchOptions glitchOptions = new GlitchOptions(instructions);
        return glitchOptions;
    }

    public ScrollableTextArea getGlitchAddresses() {
        return glitchAddresses;
    }


    private void buildFindGlitchOuterSection() {
        // create a border
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find Glitch");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        // add the border to the current panel
        this.setBorder(borderMPO);
        // add a layout with north/south/east/west/center components
        this.setLayout(new BorderLayout());

        // set the center component
        this.add(buildGlitchOptionsPanel(), BorderLayout.CENTER);

        // add a run button as south component
        JPanel buttonPanel = new JPanel();
        JButton runButton = new JButton("RUN");
        runButton.addActionListener(actionListener -> {
            // on click -> send the request to python
            this.provider.sendRequestToPython();
        });
        buttonPanel.add(runButton);
        this.add(buttonPanel, BorderLayout.SOUTH);
    }
}

