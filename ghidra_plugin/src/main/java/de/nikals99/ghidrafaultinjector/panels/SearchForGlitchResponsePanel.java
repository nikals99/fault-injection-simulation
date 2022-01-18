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
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Found possible glitches at:");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        this.setBorder(borderMPO);
        this.setLayout(new BorderLayout());

        listPanel = new ListPanel();
        searchForGlitchResponseDefaultListModel = new DefaultListModel<SearchForGlitchResponse>();

        this.add(listPanel, BorderLayout.CENTER);
        listPanel.setListModel(searchForGlitchResponseDefaultListModel);

        listPanel.setListSelectionListener(listener -> {
            if(listPanel.getSelectedIndex() < 0) {
                return;
            }
            pathListPanel.setSelectedIndex(-1);
            FlatProgramAPI api = new FlatProgramAPI(program);
            int TransactionID = program.startTransaction("SetColor");
            if(previousSelection > -1) {
                Address address = api.toAddr(searchForGlitchResponseDefaultListModel.get(previousSelection).getGlitchAddress());
                colorizingService.clearBackgroundColor(address, address);
            }

            SearchForGlitchResponse current = searchForGlitchResponseDefaultListModel.get(listPanel.getSelectedIndex());
            previousSelection = listPanel.getSelectedIndex();
            Address address = api.toAddr(current.getGlitchAddress());
            colorizingService.setBackgroundColor(address, address, new Color(255, 0, 0));

            program.endTransaction(TransactionID, true);

            pathDefaultListModel.clear();
            pathDefaultListModel.addAll(current.getPaths());

            this.add(pathListPanel, BorderLayout.SOUTH);
        });

        pathListPanel = new ListPanel();
        pathDefaultListModel = new DefaultListModel<>();
        pathListPanel.setListModel(pathDefaultListModel);


        pathListPanel.setListSelectionListener(listener -> {
            if(pathListPanel.getSelectedIndex() < 0) {
                return;
            }
            Path selectedPath = pathDefaultListModel.get(pathListPanel.getSelectedIndex());
            FlatProgramAPI api = new FlatProgramAPI(program);

            int TransactionID = program.startTransaction("SetColor");
            colorizingService.clearBackgroundColor(program.getMinAddress(), program.getMaxAddress());
            selectedPath.getBlocks().forEach(block -> {
                Address firstAddress = api.toAddr(block.getAddress());
                Address lastAddress = api.toAddr(block.getInstructionAddrs().get(block.getInstructionAddrs().size()-1));

                colorizingService.setBackgroundColor(firstAddress, lastAddress, Color.pink);
            });
            SearchForGlitchResponse current = searchForGlitchResponseDefaultListModel.get(listPanel.getSelectedIndex());
            previousSelection = listPanel.getSelectedIndex();
            Address address = api.toAddr(current.getGlitchAddress());
            colorizingService.setBackgroundColor(address, address, new Color(255, 0, 0));


            program.endTransaction(TransactionID, true);
        });
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
