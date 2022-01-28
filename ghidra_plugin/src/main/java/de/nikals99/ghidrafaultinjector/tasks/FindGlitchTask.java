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

        // get the directory in which this plugin is installed
        String installationDir = getInstallationDir();
        // setup path variables
        this.tmpPath = installationDir + "/tmp";
        this.pythonScriptPath = installationDir + "/py_scripts/main.py";
    }

    @Override
    public void run(TaskMonitor taskMonitor) throws CancelledException {
        // create an object mapper that is responsible for converting object -> yaml and vice versa
        ObjectMapper om = new ObjectMapper(new YAMLFactory());

        try {
            //try to write the request to yaml
            om.writeValue(new File(this.tmpPath + "/export.yaml"), request);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // execute the python script
        System.out.println("Running " + " python3 " + " -u " + this.pythonScriptPath + this.tmpPath);
        runCommand("python3", "-u", this.pythonScriptPath, this.tmpPath);

        ArrayList<SearchForGlitchResponse> resp = new ArrayList<>();
        try {
            // convert the response yaml into a response object
            resp = om.readValue(new File(this.tmpPath + "/output.yaml"), new TypeReference<ArrayList<SearchForGlitchResponse>>() {});
        } catch (Exception e) {
            e.printStackTrace();
        }

        // make the response visible in GUI
        searchForGlitchResponsePanel.setValues(resp);
    }

    private void runCommand(String... command) {
        // Create a new processbuilder that runs the command
        ProcessBuilder pb = new ProcessBuilder(command);
        // redirect the error stream to the stdout so they can be captured at the same time
        pb.redirectErrorStream(true);

        // get a consoleservice instance. It is used to write log messages to ghidras scripting console
        ConsoleService consoleService = plugin.getTool().getService(ConsoleService.class);
        if (consoleService == null) {
            System.out.println("Can't find consoleService service");
            return;
        }
        consoleService.println("Starting ....");

        try {
            // Run the command
            Process p = pb.start();
            // create a buffer that stores stdout/stderr
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            // read the output line by line and write it to ghidras scripting console
            String line = "";
            while ((line = reader.readLine()) != null) {
                consoleService.println(line);
            }
            // close the reader
            reader.close();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    private String getInstallationDir() {
        // get a list of all possible plugin/extension installation directories
        List<ResourceFile> installationDirs = Application.getApplicationLayout().getExtensionInstallationDirs();

        // Iterate over them
        for (int i = 0; i < installationDirs.size(); i++) {
            // check if our plugin is installed in the current directory
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
