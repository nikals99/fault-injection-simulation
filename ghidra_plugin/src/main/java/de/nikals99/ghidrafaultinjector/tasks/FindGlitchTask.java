package de.nikals99.ghidrafaultinjector.tasks;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import de.nikals99.ghidrafaultinjector.model.SearchForGlitchRequest;
import de.nikals99.ghidrafaultinjector.model.SearchForGlitchResponse;
import de.nikals99.ghidrafaultinjector.panels.SearchForGlitchResponsePanel;
import generic.jar.ResourceFile;
import ghidra.app.services.ConsoleService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class FindGlitchTask extends Task {
    private Plugin plugin;
    private SearchForGlitchRequest request;
    private SearchForGlitchResponsePanel searchForGlitchResponsePanel;
    private String pythonScriptPath;
    private String tmpPath;

    public FindGlitchTask(Plugin plugin, SearchForGlitchRequest request, SearchForGlitchResponsePanel searchForGlitchResponsePanel) {
        super("Find Glitch", false, false, false, false);
        this.plugin = plugin;
        this.request = request;
        this.searchForGlitchResponsePanel = searchForGlitchResponsePanel;
        String installationDir = getInstallationDir();
        this.tmpPath = installationDir + "/tmp";
        this.pythonScriptPath = installationDir + "/py_scripts/main.py";
    }

    @Override
    public void run(TaskMonitor taskMonitor) throws CancelledException {
        ObjectMapper om = new ObjectMapper(new YAMLFactory());

        try {
            om.writeValue(new File(this.tmpPath + "/export.yaml"), request);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Running " + " python3 " + " -u " + this.pythonScriptPath + this.tmpPath);
        runCommand("python3", "-u", this.pythonScriptPath, this.tmpPath);

        ArrayList<SearchForGlitchResponse> resp = new ArrayList<>();
        try {
            resp = om.readValue(new File(this.tmpPath + "/output.yaml"), new TypeReference<ArrayList<SearchForGlitchResponse>>() {
            });
        } catch (Exception e) {
            e.printStackTrace();
        }

        searchForGlitchResponsePanel.setValues(resp);
    }

    private void runCommand(String... command) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        ConsoleService consoleService = plugin.getTool().getService(ConsoleService.class);
        if (consoleService == null) {
            System.out.println("Can't find consoleService service");
            return;
        }
        consoleService.println("Starting ....");
        try {
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            while ((line = reader.readLine()) != null) {
                consoleService.println(line);
            }
            reader.close();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    private String getInstallationDir() {
        List<ResourceFile> installationDirs = Application.getApplicationLayout().getExtensionInstallationDirs();
        for (int i = 0; i < installationDirs.size(); i++) {
            String dir =  installationDirs.get(i).getAbsolutePath() + "/ghidra-faultinjector";
            System.out.println("Searching for plugin dir in: " + dir);
            File f = new File(dir);
            if (f.exists() && f.isDirectory()) {
                return dir;
            }
        }
        return "";
    }
}
