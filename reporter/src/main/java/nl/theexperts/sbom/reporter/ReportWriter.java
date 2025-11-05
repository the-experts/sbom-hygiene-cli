package nl.theexperts.sbom.reporter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.jcup.sarif_2_1_0.model.*;
import jakarta.inject.Singleton;
import nl.theexperts.sbom.api.validation.RuleFinding;
import nl.theexperts.sbom.api.validation.ValidationSummary;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

@Singleton
public class ReportWriter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public void writeReport(Path outputFile, Path sbomFilePath, List<ValidationSummary> results) {
        var reportContent = "";
        try {
            reportContent = generateReport(sbomFilePath, results);
            writeJson(outputFile, reportContent);
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate report", e);
        }
    }

    void writeJson(Path target, String json) throws IOException {
        Files.createDirectories(target.getParent());
        Files.writeString(
                target,
                json,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );
    }

    public String generateReport(Path sbomFilePath, List<ValidationSummary> validationResult) throws JsonProcessingException {
        Run run = new Run();
        run.setTool(generateTool());

        run.setArtifacts(generateArtifact(sbomFilePath));

        for (ValidationSummary validationSummary : validationResult) {
            if (!validationSummary.success()) {
                for(RuleFinding finding: validationSummary.findings()) {
                    Result result = new Result();
                    Message message = new Message();
                    message.setText(String.join(", ", finding.messages()));
                    result.setMessage(message);
                    result.setLevel(Result.Level.ERROR);
                    result.setRuleId(finding.ruleId());
                    run.getResults().add(result);
                }
            }
        }

        SarifSchema210 sarif = new SarifSchema210();
        sarif.set$schema(URI.create("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"));
        sarif.getRuns().add(run);

        return objectMapper.writeValueAsString(sarif);
    }

    private Set<Artifact> generateArtifact(Path sbomFilePath) {
        Artifact artifact = new Artifact();
        ArtifactLocation artifactLocation = new ArtifactLocation();
        artifactLocation.setUri(sbomFilePath.toString());
        artifact.setLocation(artifactLocation);

        return Set.of(artifact);
    }

    private static Tool generateTool() {
        ToolComponent driver = new ToolComponent();
        driver.setFullName("Third-party Module Investigator");
        driver.setName("TMI");
        driver.setInformationUri(URI.create("https://github.com/the-experts/sbom-hygiene-cli"));

        Tool tool = new Tool();
        //TODO get rules from dependency validator
        tool.setDriver(driver);

        return tool;
    }

}
