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
        JPanel panel = new JPanel();
        panel.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.setBorder(borderMPO);

        panel.setLayout(new VariableHeightPairLayout());

        glitchAddresses = new ScrollableTextArea(5, 25);
        JScrollPane avoidAddrsScrollPane = new JScrollPane(glitchAddresses);
        panel.add(new GLabel("Glitch addresses:", SwingConstants.RIGHT));
        panel.add(avoidAddrsScrollPane);

        return panel;
    }

    public GlitchOptions getGlitchOptions() {
        String[] instructionAddrs = glitchAddresses.getText().split("\n");
        ArrayList<Instruction> instructions = new ArrayList<>();

        for (String instructionAddr : instructionAddrs) {
            instructions.add(new Instruction(instructionAddr));
        }

        GlitchOptions glitchOptions = new GlitchOptions(instructions);
        return glitchOptions;
    }

    public ScrollableTextArea getGlitchAddresses() {
        return glitchAddresses;
    }


    private void buildFindGlitchOuterSection() {
        this.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find Glitch");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        this.setBorder(borderMPO);
        this.setLayout(new BorderLayout());

        this.add(buildGlitchOptionsPanel(), BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        JButton runButton = new JButton("RUN");
        runButton.addActionListener(actionListener -> {
            this.provider.sendRequestToPython();
        });
        buttonPanel.add(runButton);

        this.add(buttonPanel, BorderLayout.SOUTH);
    }
}

