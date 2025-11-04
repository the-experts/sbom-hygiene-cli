package nl.theexperts.sbom.collector;

public class VcsCollectionException extends RuntimeException {

    private final String url;

    public VcsCollectionException(String url, Throwable e) {
        super("Could not reach VCS repository " + url, e);
        this.url = url;
    }

    public VcsCollectionException(String message, String url, Throwable e) {
        super(message, e);
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

}
