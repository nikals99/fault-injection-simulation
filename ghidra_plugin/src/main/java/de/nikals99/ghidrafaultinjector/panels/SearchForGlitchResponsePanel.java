package de.nikals99.ghidrafaultinjector.panels;

import de.nikals99.ghidrafaultinjector.model.Path;
import de.nikals99.ghidrafaultinjector.model.SearchForGlitchResponse;
import docking.widgets.list.ListPanel;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.List;

public class SearchForGlitchResponsePanel extends JPanel {
    private DefaultListModel<SearchForGlitchResponse> searchForGlitchResponseDefaultListModel;
    private DefaultListModel<Path> pathDefaultListModel;
    private Program program;
    private ColorizingService colorizingService;
    private int previousSelection = -1;
    private ListPanel listPanel;
    private ListPanel pathListPanel;

    public SearchForGlitchResponsePanel(Program program, ColorizingService colorizingService) {
        super();
        this.program = program;
        this.colorizingService = colorizingService;
        buildSearchForGlitchResponsePanel();
    }

    private void buildSearchForGlitchResponsePanel() {
        // Create a border
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Found possible glitches at:");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));

        // add the border to the current panel
        this.setBorder(borderMPO);

        // add a layout with north/south/east/west/center components
        this.setLayout(new BorderLayout());

        // Create a new ListPanel that holds all found glitches
        listPanel = new ListPanel();
        this.add(listPanel, BorderLayout.CENTER);
        // create and set the ListModel
        searchForGlitchResponseDefaultListModel = new DefaultListModel<SearchForGlitchResponse>();
        listPanel.setListModel(searchForGlitchResponseDefaultListModel);

        // on selection mark the selected address red
        listPanel.setListSelectionListener(listener -> {
            if(listPanel.getSelectedIndex() < 0) {
                //if no item is selected return
                return;
            }
            // deselect items in the sub list
            pathListPanel.setSelectedIndex(-1);
            // get an instance of flatProgramApi
            FlatProgramAPI api = new FlatProgramAPI(program);
            // start a transaction
            int TransactionID = program.startTransaction("SetColor");

            // Clear the color of a previously selected item
            if(previousSelection > -1) {
                Address address = api.toAddr(searchForGlitchResponseDefaultListModel.get(previousSelection).getGlitchAddress());
                colorizingService.clearBackgroundColor(address, address);
            }

            // get the address of the currently selected item and color it red
            SearchForGlitchResponse current = searchForGlitchResponseDefaultListModel.get(listPanel.getSelectedIndex());
            previousSelection = listPanel.getSelectedIndex();
            Address address = api.toAddr(current.getGlitchAddress());
            colorizingService.setBackgroundColor(address, address, new Color(255, 0, 0));

            // end the transaction
            program.endTransaction(TransactionID, true);

            // clear and repopulate the sublist
            pathDefaultListModel.clear();
            pathDefaultListModel.addAll(current.getPaths());
        });

        // create a second list that contains all path leading to the selected glitch
        pathListPanel = new ListPanel();

        // create a second ListModel and add it to the pathlist
        pathDefaultListModel = new DefaultListModel<>();
        pathListPanel.setListModel(pathDefaultListModel);

        //on selection
        pathListPanel.setListSelectionListener(listener -> {
            if(pathListPanel.getSelectedIndex() < 0) {
                //if no item is selected return
                return;
            }
            // get the currently selected path
            Path selectedPath = pathDefaultListModel.get(pathListPanel.getSelectedIndex());

            // get an instance of FlatProgramAPI
            FlatProgramAPI api = new FlatProgramAPI(program);

            // start a new transaction
            int TransactionID = program.startTransaction("SetColor");
            // clear all colors
            colorizingService.clearBackgroundColor(program.getMinAddress(), program.getMaxAddress());

            // for each block in the path
            selectedPath.getBlocks().forEach(block -> {
                // get the firstAddress
                Address firstAddress = api.toAddr(block.getAddress());
                Address lastAddress;
                //Get the last address (is equal to first address when block only contains one address)
                if (block.getInstructionAddrs().size() > 1) {
                    lastAddress = api.toAddr(block.getInstructionAddrs().get(block.getInstructionAddrs().size()-1));
                } else {
                    lastAddress = firstAddress;
                }
                // color the whole block pink
                colorizingService.setBackgroundColor(firstAddress, lastAddress, Color.pink);
            });
            // get the currently selected glitch
            SearchForGlitchResponse current = searchForGlitchResponseDefaultListModel.get(listPanel.getSelectedIndex());
            previousSelection = listPanel.getSelectedIndex();
            Address address = api.toAddr(current.getGlitchAddress());

            // color the currently selected glitch in red
            colorizingService.setBackgroundColor(address, address, new Color(255, 0, 0));

            // end the transaction
            program.endTransaction(TransactionID, true);
        });

        // add the sublist
        this.add(pathListPanel, BorderLayout.SOUTH);
    }


    public void setValues(List<SearchForGlitchResponse> response) {
        previousSelection = -1;
        listPanel.setSelectedIndex(-1);
        searchForGlitchResponseDefaultListModel.clear();
        searchForGlitchResponseDefaultListModel.addAll(response);
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void setColorizingService(ColorizingService colorizingService) {
        this.colorizingService = colorizingService;
    }
}
