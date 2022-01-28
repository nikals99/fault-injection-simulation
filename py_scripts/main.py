from analyzer import Analyzer
import yaml
import sys


if __name__ == '__main__':
    """
    This tool is used by the ghidra plugin to find glitches. argv[1] needs to be the path to the yaml exported by the plugin
    """
    # get the yaml_path from argv
    yaml_path = sys.argv[1]
    print(f"loading yaml from {yaml_path}\n")
    # load the yaml file
    yaml_file = open(f"{yaml_path}/export.yaml", 'r')
    # convert the yaml into a dictionary.
    # unsafe load needs to be used since the yaml contains code that needs to be executed
    options = yaml.unsafe_load(yaml_file)

    # Hack to get custom functions working. This only works in __main__ but not in other functions
    if not options["findOptions"]["useCustomFindFunction"]:
        # if a find address is used set it in options
        options["find"] = int(options["findOptions"]["findAddress"], 16)
    else:
        # if a custom find function is used load it using exec and store it in options
        custom_find = ()
        print(custom_find)
        exec(options["findOptions"]["customFindFunction"])
        print(custom_find)
        options["find"] = custom_find

    # create the analyzer object that is used to simulate the glitches
    analyzer = Analyzer(options)

    # actually search for glitches
    found = analyzer.glitch()

    # write the found glitches back to yaml
    output_file = open(f"{yaml_path}/output.yaml", "w")
    yaml.safe_dump(found, output_file)

