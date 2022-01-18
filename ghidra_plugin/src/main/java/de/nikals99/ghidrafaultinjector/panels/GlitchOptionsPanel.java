package de.nikals99.ghidrafaultinjector.panels;

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

    public GlitchOptionsPanel() {
        super();
        buildGlitchOptionsPanel();
    }

    private void buildGlitchOptionsPanel() {
        this.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        this.setBorder(borderMPO);

        this.setLayout(new VariableHeightPairLayout());

        glitchAddresses = new ScrollableTextArea(5, 25);
        JScrollPane avoidAddrsScrollPane = new JScrollPane(glitchAddresses);
        this.add(new GLabel("Glitch addresses:", SwingConstants.RIGHT));
        this.add(avoidAddrsScrollPane);
    }

    public GlitchOptions getGlitchOptions() {
        String[] instructionAddrs = glitchAddresses.getText().split("\n");
        ArrayList<Instruction> instructions = new ArrayList<>();

        for (String instructionAddr : instructionAddrs) {
            instructions.add(new Instruction(instructionAddr, false));
        }

        GlitchOptions glitchOptions = new GlitchOptions(instructions);
        return glitchOptions;
    }

    public ScrollableTextArea getGlitchAddresses() {
        return glitchAddresses;
    }
}

