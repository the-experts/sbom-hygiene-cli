package nl.theexperts.sbom.collector;

import jakarta.enterprise.context.ApplicationScoped;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;
import nl.theexperts.sbom.api.VcsType;

import java.net.URL;

@ApplicationScoped
public class DependencyHygieneCollector {

    private final FetcherSelector fetcherSelector;

    public DependencyHygieneCollector(final FetcherSelector fetcherSelector) {
        this.fetcherSelector = fetcherSelector;
    }

    public SourceCodeRepositoryHygiene collect(URL url, char[] token) {
        var fetcher = fetcherSelector.selectFetcher(VcsType.find(url.getHost()), token);
        if (fetcher == null) {
            throw new VcsTypeNotSupportedException(VcsType.OTHER, url.toString());
        }
        return fetcher.fetch(url);
    }

}
