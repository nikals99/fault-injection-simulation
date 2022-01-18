package de.nikals99.ghidrafaultinjector.panels;

import de.nikals99.ghidrafaultinjector.model.FindOptions;
import docking.widgets.ScrollableTextArea;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.util.layout.VariableHeightPairLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class FindOptionsPanel extends JPanel {
    private JTextField findAddressTextField;
    private ScrollableTextArea avoidAddrsTextArea;
    private GCheckBox useCustomFindFunctionCheckBox;
    private ScrollableTextArea customFindFunction;

    public FindOptionsPanel() {
        super();
        buildFindOptionsPanel();
    }

    private void buildFindOptionsPanel() {
        this.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        this.setBorder(borderMPO);

        this.setLayout(new VariableHeightPairLayout());

        //Create all the components needed
        findAddressTextField = new JTextField();
        findAddressTextField.setPreferredSize(new Dimension(80, 20));
        this.add(new GLabel("Find Address:", SwingConstants.RIGHT));
        this.add(findAddressTextField);

        avoidAddrsTextArea = new ScrollableTextArea(5, 25);
        JScrollPane avoidAddrsScrollPane = new JScrollPane(avoidAddrsTextArea);
        this.add(new GLabel("Avoid Addresses:", SwingConstants.RIGHT));
        this.add(avoidAddrsScrollPane);

        useCustomFindFunctionCheckBox = new GCheckBox();
        this.add(new GLabel("Use custom find function:", SwingConstants.RIGHT));
        this.add(useCustomFindFunctionCheckBox);

        customFindFunction = new ScrollableTextArea(10, 25);
        customFindFunction.setVisible(false);
        GLabel customFindFunctionLabel = new GLabel("Custom Find function:", SwingConstants.RIGHT);
        customFindFunctionLabel.setVisible(false);
        this.add(customFindFunctionLabel);
        this.add(customFindFunction);

        useCustomFindFunctionCheckBox.addItemListener(item -> {
            customFindFunctionLabel.setVisible(useCustomFindFunctionCheckBox.isSelected());
            customFindFunction.setVisible(useCustomFindFunctionCheckBox.isSelected());
            this.revalidate();
        });
    }

    public FindOptions getFindOptions() {
        FindOptions findOptions = new FindOptions(
                findAddressTextField.getText(),
                avoidAddrsTextArea.getText().split("\n"),
                useCustomFindFunctionCheckBox.isSelected(),
                customFindFunction.getText()
        );
        return findOptions;
    }

    public void setFindAddress(String address) {
        this.findAddressTextField.setText(address);
    }

    public ScrollableTextArea getAvoidAddrsTextArea() {
        return avoidAddrsTextArea;
    }
}
