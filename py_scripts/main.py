from analyzer import Analyzer
import yaml
import sys

if __name__ == '__main__':
    yaml_path = sys.argv[1]
    print(f"loading yaml from {yaml_path}\n")
    yaml_file = open(f"{yaml_path}/export.yaml", 'r')
    options = yaml.unsafe_load(yaml_file)
    #Hack to get custom functions working. This only works in __main__ :shrug:
    if not options["findOptions"]["useCustomFindFunction"]:
        options["find"] = int(options["findOptions"]["findAddress"], 16)
    else:
        custom_find = ()
        print(custom_find)
        exec(options["findOptions"]["customFindFunction"])
        print(custom_find)
        options["find"] = custom_find

    analyzer = Analyzer(options)

    found = analyzer.glitch()
    output_file = open(f"{yaml_path}/output.yaml", "w")
    yaml.safe_dump(found, output_file)

