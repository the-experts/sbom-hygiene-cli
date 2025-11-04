# cli-parent
The SBOM Hygiene CLI helps you to keep your dependencies tidy and neat

## Native build
In order to build a native executable you will need to have [GraalVM JDK25](https://quarkus.io/guides/building-native-image)
installed.

First package the application using:
```shell
mvn clean package -DskipTests
```

Now create a native build using:
```shell
mvn -Pnative -pl cli-runner -am -DskipTests package
```

The executable can be found in `cli-runner/target/cli-runner-${version}-runner`