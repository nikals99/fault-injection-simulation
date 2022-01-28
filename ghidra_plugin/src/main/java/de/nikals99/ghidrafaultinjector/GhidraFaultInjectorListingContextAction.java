package de.nikals99.ghidrafaultinjector;

import docking.ActionContext;
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
    private Address currentBlankStateAddress;
    private List<Address> glitchAddresses;
    private List<Address> avoidAddresses;

    public GhidraFaultInjectorListingContextAction(GhidraFaultInjectorPlugin plugin, Program program) {
        super("GhidraFaultInjectorPlugin", plugin.getName());
        // initialize variables
        this.program = program;
        this.pluginTool = plugin.getTool();
        this.plugin = plugin;
        this.glitchAddresses = new ArrayList<>();
        this.avoidAddresses = new ArrayList<>();

        // setup the context Actions
        setupActions();
    }

    public void setupActions() {
        // Create a new Menu
        pluginTool.setMenuGroup(new String[]{
                MENUNAME
        }, GROUPNAME);

        // create findAddressActions
        findAddressActions();
        // create glitchAddressActions
        glitchAddressActions();
        // create blankStateActions
        blankStateActions();
        // create avoidAddressActions
        avoidAddressActions();
    }

    private void blankStateActions() {
        // Create the action
        ListingContextAction setBlankStateAddress = new ListingContextAction("Set BlankState Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                if (currentBlankStateAddress != null) {
                    unSetColor(currentBlankStateAddress);
                }
                currentBlankStateAddress = address;
                setColor(address, Color.BLUE);
                plugin.provider.mainOptionsPanel.setBlankState("0x" + address.toString());
            }
        };
        setBlankStateAddress.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Set",
                "BlankState Address"
        }));
        // finally add the action
        pluginTool.addAction(setBlankStateAddress);

        // Create the clear action
        ListingContextAction clearBlankStateAddress = new ListingContextAction("Clear BlankState Address", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (currentBlankStateAddress != null) {
                    unSetColor(currentBlankStateAddress);
                }
                currentBlankStateAddress = null;
                plugin.provider.mainOptionsPanel.clearBlankState();
            }
        };
        clearBlankStateAddress.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Clear",
                "BlankState Address"
        }));
        // finally add the action
        pluginTool.addAction(clearBlankStateAddress);
    }

    private void glitchAddressActions() {
        // Create the action
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
        // finally add the action
        pluginTool.addAction(setGlitchAddressAction);

        // Create the clear action
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
        // finally add the action
        pluginTool.addAction(clearGlitchAddresses);
    }

    private void findAddressActions() {
        // Create the action
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
        // finally add the action
        pluginTool.addAction(setFindAddressAction);

        // Create the clear action
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
        // finally add the action
        pluginTool.addAction(clearFindAddressAction);
    }

    private void avoidAddressActions() {
        // Create the action
        ListingContextAction addAvoidAddressAction = new ListingContextAction("Add Avoid Addresses", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                AddressSet addressSet = new AddressSet();
                addressSet.add(context.getSelection().getMinAddress(), context.getSelection().getMaxAddress());
                program.getListing().getInstructions(addressSet, true).forEach((instruction) -> {
                            avoidAddresses.add(instruction.getAddress());
                            setColor(instruction.getAddress(), Color.pink);
                        }
                );
                List<String> addressStrings = avoidAddresses.stream().map((address -> "0x" + address.toString())).collect(Collectors.toList());
                plugin.provider.findOptionsPanel.getAvoidAddrsTextArea().setText(String.join("\n", addressStrings));
            }
        };
        addAvoidAddressAction.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Add",
                "Avoid Addresses"
        }));
        // finally add the action
        pluginTool.addAction(addAvoidAddressAction);

        // Create the clear action
        ListingContextAction clearAvoidAddresses = new ListingContextAction("Clear Avoid Addresses", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                avoidAddresses.forEach(avoidAddress -> {
                    unSetColor(avoidAddress);
                });
                avoidAddresses.clear();
                plugin.provider.findOptionsPanel.getAvoidAddrsTextArea().setText("");
            }
        };
        clearAvoidAddresses.setPopupMenuData(new MenuData(new String[]{
                MENUNAME,
                "Clear",
                "Avoid Addresses"
        }));
        // finally add the action
        pluginTool.addAction(clearAvoidAddresses);
    }


    public void setProgram(Program program) {
        this.program = program;
    }

    public void unSetColor(Address address) {
        // get a colorizing service instance
        ColorizingService service = pluginTool.getService(ColorizingService.class);
        // coloring needs to be encapsulated by a transaction
        int TransactionID = program.startTransaction("UnSetColor");
        // actually unset the color
        service.clearBackgroundColor(address, address);
        // end the transaction
        program.endTransaction(TransactionID, true);

    }

    public void setColor(Address address, Color color) {
        // get a colorizing service instance
        ColorizingService service = pluginTool.getService(ColorizingService.class);
        // coloring needs to be encapsulated by a transaction
        int TransactionID = program.startTransaction("SetColor");
        // actually color the address
        service.setBackgroundColor(address, address, color);
        // end the transaction
        program.endTransaction(TransactionID, true);

    }
}
