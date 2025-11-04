package nl.theexperts.sbom.cli;

import picocli.CommandLine;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

@CommandLine.Command(name = "run-sbom-hygiene")
public class RunCommand implements Runnable {

    @CommandLine.Option(names = "--sbom-path", description = "Name of the sbom file", required = true)
    String sbomPath;

    @CommandLine.Option(names = {"-o", "--output"}, description = "Output name of the generated file", defaultValue = "sbom-hygiene.json")
    String outputPath;

    @CommandLine.Option(names = {"-i", "--input"}, description = "Path to custom ruleset json", defaultValue = "./dependency-validator/license-rules.json")
    String rulesJson;

    private RunCommand() {}

    @Override
    public void run() {
        // Resolve sbomPath to an absolute, normalized path.
        try {
            if (sbomPath == null || sbomPath.trim().isEmpty()) {
                System.err.println("No SBOM path provided");
                // Exit with code 1 instead of throwing an exception
                System.exit(1);
                return;
            }

            // Expand leading '~' to user home
            String expanded = sbomPath;
            if (expanded.startsWith("~")) {
                String userHome = System.getProperty("user.home");
                if (expanded.equals("~")) {
                    expanded = userHome;
                } else if (expanded.startsWith("~/") || expanded.startsWith("~" + File.separator)) {
                    expanded = userHome + expanded.substring(1);
                }
            }

            Path inputPath = Paths.get(expanded);
            Path absPath = inputPath.isAbsolute()
                    ? inputPath.toAbsolutePath().normalize()
                    : Paths.get(System.getProperty("user.dir")).resolve(inputPath).toAbsolutePath().normalize();

            if (!Files.exists(absPath)) {
                System.err.println("SBOM file not found: " + absPath);
                // Exit with code 1 instead of throwing an exception
                System.exit(1);
                return;
            }

            // update sbomPath to the resolved absolute path for downstream processing
            sbomPath = absPath.toString();
            System.out.println("Resolved SBOM path: " + sbomPath);

        } catch (InvalidPathException e) {
            System.err.println("Invalid SBOM path: " + sbomPath + " -> " + e.getMessage());
            // Exit with code 1 instead of throwing an exception
            System.exit(1);
            return;
        }

        System.out.println("Running sbom " + sbomPath + " with json " + rulesJson + " to output " + outputPath);
        // TODO: call processor logic here
    }

    // exit with 0 if successful or 1 if failed
    static void main(String[] args) {
        int exitCode = new CommandLine(new RunCommand()).execute(args);
        System.out.println("ExitCode: " + exitCode);
        System.exit(exitCode);
    }
}
