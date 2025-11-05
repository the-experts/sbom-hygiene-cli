package nl.theexperts.sbom.collector.fetcher;

import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@RegisterRestClient(configKey = "github")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface GitHubClient {

    @GET
    @Path("/repos/{owner}/{repo}")
    GitHubRepo getRepo(@PathParam("owner") String owner, @PathParam("repo") String repo);

    // We need headers to read Link → use Response
    @GET
    @Path("/repos/{owner}/{repo}/contributors")
    Response getContributorsPage(@PathParam("owner") String owner, @PathParam("repo") String repo,
                                 @QueryParam("per_page") @DefaultValue("1") int perPage,
                                 @QueryParam("anon") @DefaultValue("true") String anon);

    @GET
    @Path("/repos/{owner}/{repo}/releases")
    Response getReleasesPage(@PathParam("owner") String owner, @PathParam("repo") String repo,
                             @QueryParam("per_page") @DefaultValue("1") int perPage);

    @GET
    @Path("/repos/{owner}/{repo}/releases/latest")
    GitHubRelease getLatestRelease(@PathParam("owner") String owner, @PathParam("repo") String repo);

    // ---- Authorization header (Bearer PAT) ----
    @ClientHeaderParam(name = "Authorization", value = "token {token}")
    default String auth() { return "token " + token(); }

    @ConfigProperty(name = "github.token")
    String token();
}
