package nl.theexperts.sbom.api.validation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class LicenseRules {

    @JsonProperty
    private Map<String, Object> rules;

    public Map<String, Object> getRules() {
        return rules;
    }
}
