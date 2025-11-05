package nl.theexperts.sbom.collector.fetcher;

import io.quarkiverse.mockserver.test.InjectMockServerClient;
import io.quarkiverse.mockserver.test.MockServerTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.LocalDateTime;

import static nl.theexperts.sbom.collector.TestUtils.readClassPathResource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@QuarkusTest
@QuarkusTestResource(MockServerTestResource.class)
class GitHubHygieneFetcherTest {

    private static final String GITHUB_TOKEN = "abc";
    private GitHubHygieneFetcher fetcher;

    @InjectMockServerClient
    MockServerClient client;

    @BeforeEach
    void setUp() {
        var port = client.getPort();
        fetcher = new GitHubHygieneFetcher("http://localhost:" + port, GITHUB_TOKEN.toCharArray());
    }

    @Test
    void fetch_successful() throws MalformedURLException {
        var organisation = "the-experts";
        var repo = "sbom-hygiene-cli";
        client.when(request()
                        .withMethod("GET")
                        .withHeader("Authorization", "token " + GITHUB_TOKEN)
                        .withPath("/repos/" + organisation + "/" + repo))
                .respond(response()
                        .withStatusCode(200)
                        .withContentType(org.mockserver.model.MediaType.APPLICATION_JSON)
                        .withBody(readClassPathResource("github-api/get_repository.json"))
                );
        client.when(request()
                        .withMethod("GET")
                        .withHeader("Authorization", "token " + GITHUB_TOKEN)
                        .withPath("/repos/" + organisation + "/" + repo + "/releases"))
                .respond(response()
                        .withStatusCode(200)
                        .withContentType(org.mockserver.model.MediaType.APPLICATION_JSON)
                        .withBody(readClassPathResource("github-api/get_releases.json"))
                );
        client.when(request()
                        .withMethod("GET")
                        .withHeader("Authorization", "token " + GITHUB_TOKEN)
                        .withPath("/repos/" + organisation + "/" + repo + "/contributors"))
                .respond(response()
                        .withStatusCode(200)
                        .withContentType(org.mockserver.model.MediaType.APPLICATION_JSON)
                        .withBody(readClassPathResource("github-api/get_contributors.json"))
                );
        client.when(request()
                        .withMethod("GET")
                        .withHeader("Authorization", "token " + GITHUB_TOKEN)
                        .withPath("/repos/" + organisation + "/" + repo + "/releases/latest"))
                .respond(response()
                        .withStatusCode(200)
                        .withContentType(org.mockserver.model.MediaType.APPLICATION_JSON)
                        .withBody(readClassPathResource("github-api/get_latest_release.json"))
                );

        var url = URI.create("https://github.com/the-experts/sbom-hygiene-cli").toURL();
        var result = fetcher.fetch(url);
        assertThat(result).isEqualTo(new SourceCodeRepositoryHygiene(
                url, new SourceCodeRepositoryHygiene.Score(
                -1,
                1,
                1,
                3,
                null,
                LocalDateTime.of(2025, 11, 4, 12, 17, 22)
        )));
    }

}
