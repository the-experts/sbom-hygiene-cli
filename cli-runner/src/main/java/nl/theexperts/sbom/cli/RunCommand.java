package nl.theexperts.sbom.cli;

import picocli.CommandLine;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

@CommandLine.Command(name = "run-sbom-hygiene")
public class RunCommand implements Runnable {

    @CommandLine.Option(names = "--sbom-path", description = "Path to the sbom file, example: ~/Downloads/sbom.json for local", required = true)
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
            boolean usedTilde = sbomPath.startsWith("~");
            expanded = getExpandedPath(expanded);

            // Determine base directory only when appropriate:
            // - If the user used a leading '~' we consider this an explicit local path and resolve relative paths against the process CWD.
            // - Otherwise, for relative paths prefer the detected CI/pipeline workspace if present.
            Path inputPath = Paths.get(expanded);
            Path absPath;
            if (inputPath.isAbsolute()) {
                absPath = inputPath.toAbsolutePath().normalize();
            } else {
                Path baseDir;
                if (usedTilde) {
                    // User explicitly used ~ => treat as local; resolve relative paths against current working directory
                    baseDir = Paths.get(System.getProperty("user.dir"));
                    System.out.println("Using current working dir for relative resolution (local): " + baseDir);
                } else {
                    // No leading ~ => prefer CI/workspace detection
                    baseDir = detectWorkspaceDir().toAbsolutePath().normalize();
                }
                absPath = baseDir.resolve(inputPath).toAbsolutePath().normalize();
            }

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
        // TODO: Send SBOM to parser
        // TODO: Accept standard format back from parser
        // TODO: call processor logic here
    }

    private static String getExpandedPath(String expanded) {
        if (expanded.startsWith("~")) {
            String userHome = System.getProperty("user.home");
            if (expanded.equals("~")) {
                expanded = userHome;
            } else if (expanded.startsWith("~/") || expanded.startsWith("~" + File.separator)) {
                expanded = userHome + expanded.substring(1);
            }
        }
        return expanded;
    }

    /**
     * Detect a likely workspace directory when running in CI/pipeline environments.
     * Returns the first non-empty environment variable among common CI workspace env vars.
     * Falls back to the current working directory when none are set.
     */
    private Path detectWorkspaceDir() {
        String[] envVars = new String[] {
            "GITHUB_WORKSPACE",      // GitHub Actions
            "CI_PROJECT_DIR",       // GitLab CI
            "BUILD_SOURCESDIRECTORY", // Azure Pipelines
            "WORKSPACE",            // Jenkins
            "TRAVIS_BUILD_DIR",     // Travis CI
            "CIRCLE_WORKING_DIRECTORY", // CircleCI
            "BITBUCKET_CLONE_DIR", // Bitbucket Pipelines
            "GITLAB_CI",            // fallback indicator - but prefer CI_PROJECT_DIR
            "CI"                    // generic CI indicator
        };

        for (String v : envVars) {
            String val = System.getenv(v);
            if (val != null && !val.isBlank()) {
                // For generic CI indicators like CI or GITLAB_CI where val may be 'true', skip unless it's a path-like var
                if (v.equals("CI") || v.equals("GITLAB_CI")) {
                    // ignore boolean-like CI flags
                    continue;
                }
                System.out.println("Detected workspace from env var " + v + ": " + val);
                return Paths.get(val);
            }
        }

        // Nothing CI-specific found; use current working dir
        Path cwd = Paths.get(System.getProperty("user.dir"));
        System.out.println("No CI workspace env var detected; using current working dir: " + cwd);
        return cwd;
    }
}
