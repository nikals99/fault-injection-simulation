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
        // create a border
        TitledBorder borderMPO = BorderFactory.createTitledBorder("State Modifications");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        // add border to the current panel
        this.setBorder(borderMPO);

        // add a layout with north/south/east/west/center components
        this.setLayout(new BorderLayout());

        // add a list component that shows the current memory modifications
        ListPanel listPanel = new ListPanel();
        // create and set the ListModel for the panel
        memoryModificationDefaultListModel = new DefaultListModel();
        listPanel.setListModel(memoryModificationDefaultListModel);
        // add the listPanel to the current panel
        this.add(listPanel, BorderLayout.CENTER);

        // create a new panel for processing inputs
        JPanel inputRow = new JPanel();
        // use a ghidra layout that supports label -> input pairs
        inputRow.setLayout(new VariableHeightPairLayout());

        // create and add addressInputTextField + label
        JTextField addressInputTextField = new JTextField();
        addressInputTextField.setColumns(10);
        inputRow.add(new GLabel("Address:", SwingConstants.RIGHT));
        inputRow.add(addressInputTextField);

        // create and add valueInputTextField + label
        JTextField valueInputTextField = new JTextField();
        valueInputTextField.setColumns(10);
        inputRow.add(new GLabel("Value:", SwingConstants.RIGHT));
        inputRow.add(valueInputTextField);

        // create and add lengthInputTextField + label
        HexOrDecimalInput lengthInputTextField = new HexOrDecimalInput();
        lengthInputTextField.setColumns(2);
        inputRow.add(new GLabel("Length:", SwingConstants.RIGHT));
        inputRow.add(lengthInputTextField);

        // create and add byteOrderInputBox + label
        GComboBox<String> byteOrderInputBox = new GComboBox<>(new String[]{"BE", "LE"});
        inputRow.add(new GLabel("Byte order:", SwingConstants.RIGHT));
        inputRow.add(byteOrderInputBox);

        // Create a delete button
        JButton deleteButton = new JButton("Delete Selected");
        // On click delete the currently selected item
        deleteButton.addActionListener(actionListener -> {
            int selectedIndex = listPanel.getSelectedIndex();
            if (selectedIndex >= 0) {
                memoryModificationDefaultListModel.removeElementAt(selectedIndex);
            }
        });
        // add the button
        inputRow.add(deleteButton);

        // Create a add button
        JButton addButton = new JButton("ADD");
        //On click create a new memory modification object and add it to the list
        addButton.addActionListener(actionListener -> {
            String address = addressInputTextField.getText();
            String value = valueInputTextField.getText();
            int length = lengthInputTextField.getIntValue();

            memoryModificationDefaultListModel.addElement(new MemoryModification(address, value, length, (String)byteOrderInputBox.getSelectedItem()));

            // clear inputfields
            addressInputTextField.setText("");
            valueInputTextField.setText("");
            lengthInputTextField.setText("");
        });
        // add the button
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
