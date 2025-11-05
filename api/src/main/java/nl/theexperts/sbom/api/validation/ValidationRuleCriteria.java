package nl.theexperts.sbom.api.validation;

import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.util.HashMap;
import java.util.Map;

public class ValidationRuleCriteria {

    private final Map<String, Object> params = new HashMap<>();

    @JsonAnySetter
    public void set(String key, Object value) {
        params.put(key, value);
    }

    public Object get(String key) {
        return params.get(key);
    }

    public Map<String, Object> getParams() {
        return params;
    }
}
