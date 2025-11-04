package nl.theexperts.sbom.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

import io.quarkus.runtime.configuration.PathConverter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "run-sbom-hygiene")
public class RunCommand implements Runnable {

    @Option(
            names = {"-i", "--input"},
            description = "Path to the sbom file, example: ~/Downloads/sbom.json for local",
            required = true,
            converter = ExpandPathConverter.class
    )
    Path sbomPath;

    @Option(
            names = {"-o", "--output"},
            description = "Output name of the generated file",
            defaultValue = "sbom-hygiene.json")
    String outputPath;

    @Option(
            names = "--rules",
            description = "Path to custom ruleset json",
            defaultValue = "./dependency-validator/src/main/resources/license-rules.json")
    String rulesJson;

    private RunCommand() {}

    @Override
    public void run() {
        try {
            if (sbomPath == null) {
                System.err.println("No SBOM path provided");
                // Exit with code 1 instead of throwing an exception
                System.exit(1);
                return;
            }

            if (!Files.exists(sbomPath)) {
                System.err.println("SBOM file not found: " + sbomPath);
                // Exit with code 1 instead of throwing an exception
                System.exit(1);
                return;
            }

            System.out.println("Resolved SBOM path: " + sbomPath);

        } catch (InvalidPathException e) {
            System.err.println("Invalid SBOM path: " + sbomPath + " -> " + e.getMessage());
            // Exit with code 1 instead of throwing an exception
            System.exit(1);
            return;
        }

        System.out.println("Running sbom " + sbomPath + " with json " + rulesJson + " to output " + outputPath);
        // TODO: Send SBOM to parser
        // TODO: Accept standard format back from parser
        // TODO: call processor logic here
    }

}
