package de.nikals99.ghidrafaultinjector.panels;

import de.nikals99.ghidrafaultinjector.model.MainOptions;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.PairLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class MainOptionsPanel extends JPanel {

    private JTextField pathTextField;
    private GComboBox<String> angrBackendComboBox;
    private JTextField baseAddrTextField;
    private JTextField entryPointTextField;
    private JTextField archTextField;
    private JCheckBox blankStateCheckBox;
    private JTextField blankStateStartAtTextField;

    private Program program;

    public MainOptionsPanel(Program program) {
        super();
        this.program = program;
        buildMainOptionsPanel();
    }

    private void buildMainOptionsPanel() {
        // create a border
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Main project options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        // add a border to the current panel
        this.setBorder(borderMPO);
        // use a ghidra layout that supports label -> input pairs
        this.setLayout(new PairLayout());

        // set up the backend combobox and add it to the panel
        // available options: https://github.com/angr/angr-doc/blob/master/docs/loading.md
        angrBackendComboBox = new GComboBox<>(new String[]{"blob", "elf", "pe", "mach-o"});
        this.add(new GLabel("Loader Backend:", SwingConstants.RIGHT));
        this.add(angrBackendComboBox);

        // add archTextField + label to the current panel
        archTextField = new JTextField();
        this.add(new GLabel("Architecture:", SwingConstants.RIGHT));
        this.add(archTextField);

        // add pathTextField + label to the current panel
        pathTextField = new JTextField();
        // limit the width of the textfield
        pathTextField.setColumns(15);
        this.add(new GLabel("Path to binary:", SwingConstants.RIGHT));
        this.add(pathTextField);

        // add baseAddrTextField + label to the current panel
        baseAddrTextField = new JTextField();
        this.add(new GLabel("Base Addr:", SwingConstants.RIGHT));
        this.add(baseAddrTextField);

        // add entryPointTextField + label to the current panel
        entryPointTextField = new JTextField();
        this.add(new GLabel("Entrypoint:", SwingConstants.RIGHT));
        this.add(entryPointTextField);

        // add blankStateStartAtTextField + label
        blankStateStartAtTextField = new JTextField();
        GLabel blankStateStartAtLabel = new GLabel("Blankstate Start At:", SwingConstants.RIGHT);
        // hide blankStateStartAtTextField + label
        blankStateStartAtTextField.setVisible(false);
        blankStateStartAtLabel.setVisible(false);

        // add blankStateCheckBox
        blankStateCheckBox = new GCheckBox();
        // add a listener to the checkbox.  It is triggered on select/deselect
        blankStateCheckBox.addItemListener(item -> {
            // toggle the visibility for blankStateStartAtTextField + label
            blankStateStartAtTextField.setVisible(blankStateCheckBox.isSelected());
            blankStateStartAtLabel.setVisible(blankStateCheckBox.isSelected());
            this.revalidate();
        });
        // add labels + components to the panel
        this.add(new GLabel("Use BlankState:", SwingConstants.RIGHT));
        this.add(blankStateCheckBox);
        this.add(blankStateStartAtLabel);
        this.add(blankStateStartAtTextField);
    }

    public MainOptions getMainOptions() {
        // get all options from inputFields
        MainOptions mainOptions = new MainOptions(
                pathTextField.getText(),
                (String) angrBackendComboBox.getSelectedItem(),
                archTextField.getText(),
                entryPointTextField.getText(),
                baseAddrTextField.getText(),
                blankStateCheckBox.isSelected(),
                blankStateStartAtTextField.getText()
        );
        return mainOptions;
    }

    public void setProgram(Program program) {
        this.program = program;
        if (program != null) {
            // prefill the backend field
            switch (program.getExecutableFormat()) {
                case ElfLoader.ELF_NAME:
                    angrBackendComboBox.setSelectedIndex(1);
                    break;
                case BinaryLoader.BINARY_NAME:
                    angrBackendComboBox.setSelectedIndex(0);
                    break;
                case PeLoader.PE_NAME:
                    angrBackendComboBox.setSelectedIndex(2);
                    break;
                case MachoLoader.MACH_O_NAME:
                    angrBackendComboBox.setSelectedIndex(3);
                    break;
                default:
                    angrBackendComboBox.setSelectedIndex(0);
            }
            // prefill the archTextField
            archTextField.setText(program.getLanguageID().getIdAsString());
            // prefill the pathTextField
            pathTextField.setText(program.getExecutablePath());
            // prefill the baseAddressTextField
            baseAddrTextField.setText("0x" + program.getImageBase().toString());
            // prefill the entryPointTextField
            entryPointTextField.setText("0x" + program.getImageBase().toString());
        }
    }

    public void setBlankState(String address) {
        blankStateCheckBox.setSelected(true);
        blankStateStartAtTextField.setText(address);
    }

    public void clearBlankState() {
        blankStateCheckBox.setSelected(false);
        blankStateStartAtTextField.setText("");
    }
}
