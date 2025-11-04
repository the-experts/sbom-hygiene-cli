package nl.theexperts.sbom.collector;

import nl.theexperts.sbom.api.VcsType;

public class VcsTypeNotSupportedException extends RuntimeException {

    public VcsTypeNotSupportedException(VcsType type, String url) {
        super("VCS type " + type + " with URL " + url + " is currently not supported");
    }

}
