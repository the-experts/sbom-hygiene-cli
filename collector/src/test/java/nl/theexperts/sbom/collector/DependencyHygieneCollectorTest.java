package nl.theexperts.sbom.collector;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class DependencyHygieneCollectorTest {

    private static final String GITHUB_URL = "https://github.com/the-experts/sbom-hygiene-cli";

    private final DependencyHygieneCollector collector = new DependencyHygieneCollector();

    @Test
    void when_GitHub_vcs_url_then_return_GitHubHygieneFetcher() throws MalformedURLException {
        var uri = URI.create(GITHUB_URL).toURL();
        var result = collector.collect(uri);

        assertThat(result.url()).hasToString(GITHUB_URL);
        assertThat(result.score()).isNull();
    }

    @Test
    void when_unknown_vcs_url_then_throw_exception() throws MalformedURLException {
        var url = URI.create("https://mydomain.com/repo").toURL();
        assertThatExceptionOfType(VcsTypeNotSupportedException.class)
                .isThrownBy(() -> collector.collect(url))
                .withMessage("VCS type OTHER with URL https://mydomain.com/repo is currently not supported");
    }

}
