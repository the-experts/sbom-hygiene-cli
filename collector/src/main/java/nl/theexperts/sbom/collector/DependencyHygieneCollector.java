package nl.theexperts.sbom.collector;

import java.net.URL;

public class DependencyHygieneCollector {

    private final FetcherSelector fetcherSelector;

    public DependencyHygieneCollector(final FetcherSelector fetcherSelector) {
        this.fetcherSelector = fetcherSelector;
    }

    public SourceCodeRepositoryHygiene collect(URL uri) {
        var fetcher = fetcherSelector.selectFetcher(VcsType.find(uri.getHost()));
        if (fetcher == null) {
            throw new VcsTypeNotSupportedException(VcsType.OTHER, uri.toString());
        }
        return fetcher.fetch(uri);
    }

}
