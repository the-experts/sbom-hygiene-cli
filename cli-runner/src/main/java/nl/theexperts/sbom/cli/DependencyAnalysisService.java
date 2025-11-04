package nl.theexperts.sbom.cli;

import com.siemens.sbom.standardbom.model.BomEntry;
import jakarta.inject.Singleton;
import nl.theexperts.sbom.cli.credentials.NetrcSecretSource;
import nl.theexperts.sbom.collector.DependencyHygieneCollector;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;
import nl.theexperts.sbom.parser.SbomParser;

import java.net.MalformedURLException;
import java.net.URI;
import java.nio.file.Path;

@Singleton
public class DependencyAnalysisService {

    private final SbomParser parser;
    private final DependencyHygieneCollector collector;

    public DependencyAnalysisService(SbomParser parser, DependencyHygieneCollector collector) {
        this.parser = parser;
        this.collector = collector;
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
    }

    private char[] getTokenForUrl(String repoUrl, NetrcSecretSource credentialsSource) {
        var uri = URI.create(repoUrl);
        var vcsType = nl.theexperts.sbom.api.VcsType.find(uri.getHost());
        return credentialsSource.get(vcsType);
    }

}
