package de.nikals99.ghidrafaultinjector;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class GhidraFaultInjectorListingContextAction extends ListingContextAction {
    private static final String MENUNAME = "GhidraFaultInjector";
    private static final String GROUPNAME = "SymEx";
    private Program program;
    private PluginTool pluginTool;
    private GhidraFaultInjectorPlugin plugin;


    private Address currentFindAddress;
    private List<Address> glitchAddresses;

    public GhidraFaultInjectorListingContextAction(GhidraFaultInjectorPlugin plugin, Program program) {
        super("GhidraFaultInjectorPlugin", plugin.getName());
        this.program = program;
        this.pluginTool = plugin.getTool();
        this.plugin = plugin;
        glitchAddresses = new ArrayList<>();
        setupActions();
    }

    public void setupActions() {
        pluginTool.setMenuGroup(new String[]{
                MENUNAME
        }, GROUPNAME);

        ListingContextAction setFindAddressAction = new ListingContextAction("Set Find Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                if (currentFindAddress != null) {
                    unSetColor(currentFindAddress);
                }
                currentFindAddress = address;
                setColor(address, Color.GREEN);
                plugin.provider.findOptionsPanel.setFindAddress("0x" + address.toString());
            }
        };

        setFindAddressAction.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Set",
                "Find Address"
        }, null, GROUPNAME));
        pluginTool.addAction(setFindAddressAction);

        ListingContextAction clearFindAddressAction = new ListingContextAction("Clear Find Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                unSetColor(currentFindAddress);
                currentFindAddress = null;
                plugin.provider.findOptionsPanel.setFindAddress("");
            }
        };
        clearFindAddressAction.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Clear",
                "Find Address"
        }));
        pluginTool.addAction(clearFindAddressAction);

        ListingContextAction setGlitchAddressAction = new ListingContextAction("Add Glitch Addresses", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                AddressSet addressSet = new AddressSet();
                addressSet.add(context.getSelection().getMinAddress(), context.getSelection().getMaxAddress());
                program.getListing().getInstructions(addressSet, true).forEach((instruction) -> {
                            glitchAddresses.add(instruction.getAddress());
                            setColor(instruction.getAddress(), Color.orange);
                        }
                );
                List<String> addressStrings = glitchAddresses.stream().map((address -> "0x" + address.toString())).collect(Collectors.toList());
                plugin.provider.glitchOptionsPanel.getGlitchAddresses().setText(String.join("\n", addressStrings));
            }
        };
        setGlitchAddressAction.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Add",
                "Glitch Addresses"
        }));
        pluginTool.addAction(setGlitchAddressAction);

        ListingContextAction clearGlitchAddresses = new ListingContextAction("Clear Glitch Addresses", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                glitchAddresses.forEach(glitchAddress -> {
                    unSetColor(glitchAddress);
                });
                glitchAddresses.clear();
                plugin.provider.glitchOptionsPanel.getGlitchAddresses().setText("");
            }
        };
        clearGlitchAddresses.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Clear",
                "Glitch Addresses"
        }));
        pluginTool.addAction(clearGlitchAddresses);
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void unSetColor(Address address) {
        ColorizingService service = pluginTool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);

    }

    public void setColor(Address address, Color color) {
        ColorizingService service = pluginTool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);

    }
}