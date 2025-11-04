package nl.theexperts.sbom.cli;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;

@QuarkusMain
public class HelloWorldApp {

    public static void main(String... args) {
        Quarkus.run(HelloWorldRunner.class, args);
    }

    public static class HelloWorldRunner implements QuarkusApplication {
        @Override
        public int run(String... args) {
            System.out.println("Hello World!");
            return 0; // exit successfully
        }
    }
}
