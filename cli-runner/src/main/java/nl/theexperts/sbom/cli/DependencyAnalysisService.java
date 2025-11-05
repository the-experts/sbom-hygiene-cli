package nl.theexperts.sbom.cli;

import com.siemens.sbom.standardbom.model.BomEntry;
import jakarta.inject.Singleton;
import nl.theexperts.sbom.cli.credentials.NetrcSecretSource;
import nl.theexperts.sbom.collector.DependencyHygieneCollector;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;
import nl.theexperts.sbom.dependencyvalidator.RuleEngine;
import nl.theexperts.sbom.dependencyvalidator.model.Dependency;
import nl.theexperts.sbom.dependencyvalidator.model.ValidationSummary;
import nl.theexperts.sbom.parser.SbomParser;

import java.net.MalformedURLException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Singleton
public class DependencyAnalysisService {

    private final SbomParser parser;
    private final DependencyHygieneCollector collector;

    public DependencyAnalysisService(SbomParser parser, DependencyHygieneCollector collector) {
        this.parser = parser;
        this.collector = collector;
    }

    void analyzeDependencyHygiene(
            Path sbomPath,
            Path outputPath,
            Path failureRulesJson,
            Path licenseRulesJson,
            Path validationRulesJson,
            Path credentialsPath
    ) {
        // Create a RuleEngine instance for this run using overrides (null uses defaults)
        RuleEngine engine = new RuleEngine(validationRulesJson, licenseRulesJson, failureRulesJson);

        List<ValidationSummary> summaries = new ArrayList<>();
        var credentialsSource = new NetrcSecretSource(credentialsPath);
        var standardBom = parser.read(sbomPath.toFile());
        for (BomEntry component : standardBom.getComponents()) {
            try {
                if (component.getRepoUrl() != null) {
                    var token = getTokenForUrl(component.getRepoUrl(), credentialsSource);
                    SourceCodeRepositoryHygiene collect = collector.collect(URI.create(component.getRepoUrl()).toURL(), token);
                    IO.println("Collected score from " + component.getRepoUrl() + ": " + collect.score());

                    // Map SourceCodeRepositoryHygiene.Score to dependency-validator's Dependency.Score
                    var s = collect.score();
                    var depScore = new Dependency.Score(
                            s.downloads(),
                            s.stars(),
                            s.releases(),
                            s.contributors(),
                            s.firstReleaseDateTime(),
                            s.lastReleaseDateTime()
                    );

                    String licenseId = component.getLicenses().toString();

                    java.net.URL repoUrl = URI.create(component.getRepoUrl()).toURL();
                    Dependency dependency = new Dependency(repoUrl, depScore, licenseId);

                    // Validate the dependency using the RuleEngine directly
                    var summary = engine.evaluate(dependency);
                    IO.println("Validation summary for " + component.getName() + ": success=" + summary.success() + ", score=" + summary.score());
                    summaries.add(summary);
                }
            } catch (MalformedURLException | RuntimeException e) {
                System.err.println("Error processing component " + component.getName() + ": " + e.getMessage());
            }

            // TODO: Push the summaries to the reporter
        }
    }

    private char[] getTokenForUrl(String repoUrl, NetrcSecretSource credentialsSource) {
        var uri = URI.create(repoUrl);
        var vcsType = nl.theexperts.sbom.api.VcsType.find(uri.getHost());
        return credentialsSource.get(vcsType);
    }

}
