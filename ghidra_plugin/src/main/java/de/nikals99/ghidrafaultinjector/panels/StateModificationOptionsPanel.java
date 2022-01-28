package de.nikals99.ghidrafaultinjector.panels;

import de.nikals99.ghidrafaultinjector.model.MemoryModification;
import de.nikals99.ghidrafaultinjector.model.StateModificationOptions;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.list.ListPanel;
import docking.widgets.textfield.HexOrDecimalInput;
import ghidra.util.layout.VariableHeightPairLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Collections;

public class StateModificationOptionsPanel extends JPanel {
    private DefaultListModel<MemoryModification> memoryModificationDefaultListModel;

    public StateModificationOptionsPanel() {
        super();
        buildStateModificationOptionsPanel();
    }
    
    private void buildStateModificationOptionsPanel() {
        this.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("State Modifications");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        this.setBorder(borderMPO);
        this.setLayout(new BorderLayout());

        ListPanel listPanel = new ListPanel();
        memoryModificationDefaultListModel = new DefaultListModel();

        this.add(listPanel, BorderLayout.CENTER);
        listPanel.setListModel(memoryModificationDefaultListModel);

        JPanel inputRow = new JPanel();
        inputRow.setLayout(new VariableHeightPairLayout());

        JTextField addressInputTextField = new JTextField();
        addressInputTextField.setColumns(10);
        inputRow.add(new GLabel("Address:", SwingConstants.RIGHT));
        inputRow.add(addressInputTextField);

        JTextField valueInputTextField = new JTextField();
        valueInputTextField.setColumns(10);
        inputRow.add(new GLabel("Value:", SwingConstants.RIGHT));
        inputRow.add(valueInputTextField);

        HexOrDecimalInput lengthInputTextField = new HexOrDecimalInput();
        lengthInputTextField.setColumns(2);
        inputRow.add(new GLabel("Length:", SwingConstants.RIGHT));
        inputRow.add(lengthInputTextField);

        GComboBox<String> byteOrderInputBox = new GComboBox<>(new String[]{"BE", "LE"});
        inputRow.add(new GLabel("Byte order:", SwingConstants.RIGHT));
        inputRow.add(byteOrderInputBox);

        JButton deleteButton = new JButton("Delete Selected");
        deleteButton.addActionListener(actionListener -> {
            int selectedIndex = listPanel.getSelectedIndex();
            if (selectedIndex >= 0) {
                memoryModificationDefaultListModel.removeElementAt(selectedIndex);
            }
        });
        inputRow.add(deleteButton);

        JButton addButton = new JButton("ADD");
        addButton.addActionListener(actionListener -> {
            String address = addressInputTextField.getText();
            String value = valueInputTextField.getText();
            int length = lengthInputTextField.getIntValue();

            memoryModificationDefaultListModel.addElement(new MemoryModification(address, value, length, (String)byteOrderInputBox.getSelectedItem()));

            addressInputTextField.setText("");
            valueInputTextField.setText("");
            lengthInputTextField.setText("");
        });
        inputRow.add(addButton);

        this.add(inputRow, BorderLayout.SOUTH);
    }

    public StateModificationOptions getStateModificationOptions() {
        StateModificationOptions stateModificationOptions = new StateModificationOptions(
                Collections.list(memoryModificationDefaultListModel.elements())
        );
        return stateModificationOptions;
    }
}
