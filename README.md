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

The native executable can be found in `cli-runner/target/tmi-runner`

## Running the application
You can run the JAR application using the following command:
```shell
java -jar cli-runner/target/quarkus-app/quarkus-run.jar -i parser/src/test/resources/syft-bom.json
```
or if you have built the native executable you can run it using:
```shell
./cli-runner/target/tmi-runner -i parser/src/test/resources/syft-bom.json
````

### Authentication
To fetch information from the remote repositories you will need to provide authentication details. Authentication is performed
using a personal access token (PAT). These tokens can be stored in a file that follows the [.netrc](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html)
format. The file path can be specified on the command line using the `--credentials-file` option.

Example file:
```.netrc
machine api.github.com login token password ghp_***
```