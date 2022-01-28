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
        // create a border
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Find options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        // add the border to the current panel
        this.setBorder(borderMPO);

        // use a ghidra layout that supports label -> input pairs
        this.setLayout(new VariableHeightPairLayout());

        // create addressTextfield + label and add them
        findAddressTextField = new JTextField();
        findAddressTextField.setPreferredSize(new Dimension(80, 20));
        this.add(new GLabel("Find Address:", SwingConstants.RIGHT));
        this.add(findAddressTextField);

        // create avoidAddress TextArea + label and add them
        avoidAddrsTextArea = new ScrollableTextArea(5, 25);
        JScrollPane avoidAddrsScrollPane = new JScrollPane(avoidAddrsTextArea);
        this.add(new GLabel("Avoid Addresses:", SwingConstants.RIGHT));
        this.add(avoidAddrsScrollPane);

        // create a checkbox + label for the customFind function
        useCustomFindFunctionCheckBox = new GCheckBox();
        this.add(new GLabel("Use custom find function:", SwingConstants.RIGHT));
        this.add(useCustomFindFunctionCheckBox);

        // create the textArea for the custom find function
        customFindFunction = new ScrollableTextArea(10, 25);
        // hide the textArea
        customFindFunction.setVisible(false);
        GLabel customFindFunctionLabel = new GLabel("Custom Find function:", SwingConstants.RIGHT);
        // hide the label
        customFindFunctionLabel.setVisible(false);
        this.add(customFindFunctionLabel);
        this.add(customFindFunction);

        // add a listener to the checkbox. It is triggered on select/deselect
        useCustomFindFunctionCheckBox.addItemListener(item -> {
            // Toggle the visibility of the customFindFunction
            customFindFunctionLabel.setVisible(useCustomFindFunctionCheckBox.isSelected());
            customFindFunction.setVisible(useCustomFindFunctionCheckBox.isSelected());
            this.revalidate();
        });
    }

    public FindOptions getFindOptions() {
        String[] avoidAddrs = avoidAddrsTextArea.getText().split("\n");
        //prevent empty input
        if (avoidAddrs[0].equals("")) {
            avoidAddrs = new String[0];
        }
        // extract options from input fields
        FindOptions findOptions = new FindOptions(
                findAddressTextField.getText(),
                avoidAddrs,
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
