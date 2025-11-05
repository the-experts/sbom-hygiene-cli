package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.Dependency;
import nl.theexperts.sbom.dependencyvalidator.model.ValidationSummary;
import nl.theexperts.sbom.dependencyvalidator.model.RuleFinding;
import nl.theexperts.sbom.dependencyvalidator.model.RuleOutcome;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    @Test
    void permissiveLicenseShouldPassEnforcement() throws Exception {
        RuleEngine engine = new RuleEngine();

        var validationRules = RulesLoader.loadValidationRules(null);
        var licenseRules = RulesLoader.loadLicenseRules(null);
        var failureRules = RulesLoader.loadFailureRules(null);

        // Create a dependency whose URL contains 'MIT' so the heuristic detects the license
        Dependency.Score score = new Dependency.Score(1000, 200, 1, 5, LocalDateTime.now().minusYears(2), LocalDateTime.now());
        Dependency dep = new Dependency(URI.create("https://example.com/repos/foo/blob/main/LICENSE-MIT").toURL(), score);

        ValidationSummary summary = engine.evaluate(List.of(dep), validationRules, licenseRules, failureRules);

        assertNotNull(summary);
        List<RuleFinding> findings = summary.findings();
        assertFalse(findings.isEmpty(), "Expected some findings");

        // find license-enforcement finding
        var lic = findings.stream().filter(f -> f.ruleId().equals("license-enforcement")).findFirst();
        assertTrue(lic.isPresent(), "license-enforcement finding expected");
        assertEquals(RuleOutcome.PASS, lic.get().outcome(), "MIT should be allowed by default policy");
    }

    @Test
    void noLicenseFileShouldTriggerNoLicensePolicy() throws Exception {
        RuleEngine engine = new RuleEngine();

        var validationRules = RulesLoader.loadValidationRules(null);
        var licenseRules = RulesLoader.loadLicenseRules(null);
        var failureRules = RulesLoader.loadFailureRules(null);

        Dependency.Score score = new Dependency.Score(100, 5, 1, 1, LocalDateTime.now().minusMonths(1), LocalDateTime.now());
        Dependency dep = new Dependency(URI.create("https://example.com/repos/foo").toURL(), score);

        ValidationSummary summary = engine.evaluate(List.of(dep), validationRules, licenseRules, failureRules);
        assertNotNull(summary);

        var lic = summary.findings().stream().filter(f -> f.ruleId().equals("license-enforcement")).findFirst();
        assertTrue(lic.isPresent(), "license-enforcement finding expected");
        assertEquals(RuleOutcome.FAIL, lic.get().outcome(), "No-license-file should be configured to fail by default");
    }

}
