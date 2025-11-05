package nl.theexperts.sbom.cli;

import com.siemens.sbom.standardbom.model.BomEntry;
import jakarta.inject.Singleton;
import nl.theexperts.sbom.cli.credentials.NetrcSecretSource;
import nl.theexperts.sbom.collector.DependencyHygieneCollector;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;
import nl.theexperts.sbom.parser.SbomParser;
import nl.theexperts.sbom.reporter.ReportWriter;

import java.net.MalformedURLException;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;

@Singleton
public class DependencyAnalysisService {

    private final SbomParser parser;
    private final DependencyHygieneCollector collector;
    private final ReportWriter reportWriter;

    public DependencyAnalysisService(SbomParser parser, DependencyHygieneCollector collector, ReportWriter reportWriter) {
        this.parser = parser;
        this.collector = collector;
        this.reportWriter = reportWriter;
    }

    void analyzeDependencyHygiene(Path sbomPath, Path outputPath, Path rulesJson, Path credentialsPath) {
        var credentialsSource = new NetrcSecretSource(credentialsPath);
        var standardBom = parser.read(sbomPath.toFile());
        for (BomEntry component : standardBom.getComponents()) {
            try {
                if (component.getRepoUrl() != null) {
                    var token = getTokenForUrl(component.getRepoUrl(), credentialsSource);
                    SourceCodeRepositoryHygiene collect = collector.collect(URI.create(component.getRepoUrl()).toURL(), token);
                    IO.println("Collected score from " + component.getRepoUrl() + ": " + collect.score());
                    // TODO: call processor logic here

                }
            } catch (MalformedURLException | RuntimeException e) {
                System.err.println("Error processing component " + component.getName() + ": " + e.getMessage());
            }
        }
        reportWriter.writeReport(outputPath, sbomPath, List.of("Result 1"));
    }

    private char[] getTokenForUrl(String repoUrl, NetrcSecretSource credentialsSource) {
        var uri = URI.create(repoUrl);
        var vcsType = nl.theexperts.sbom.api.VcsType.find(uri.getHost());
        return credentialsSource.get(vcsType);
    }

}
