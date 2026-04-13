Elytron Web
===============

Integration project for integrating Elytron based HTTP authentication with web containers and clients (Initially just Undertow server)

An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

## Building From Source

```console
$ git clone git@github.com:wildfly-security/elytron-web.git
```

### Prerequisites

- **Java 25** (or later) - Required for building
- **Maven 3.9+** - For building and testing

**Note**: The project builds with Java 25 but targets Java 17 bytecode for backward compatibility.

### Setup the JBoss Maven Repository

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see http://community.jboss.org/wiki/MavenGettingStarted-Users

### Build with Maven

The command below builds the project and runs the embedded suite:

```console
$ mvn clean install
```

For detailed build instructions, testing with specific Java versions, and information about our CI system, see our [contribution guide](https://github.com/wildfly-security/elytron-web/blob/1.x/CONTRIBUTING.md#setting-up-your-developer-environment).

Issue Tracking
--------------

Bugs and features are tracked within the Elytron Jira project at https://issues.redhat.com/projects/ELYWEB

Contributions
-------------

All new features and enhancements should be submitted to 1.x branch only.

Our [contribution guide](https://github.com/wildfly-security/elytron-web/blob/1.x/CONTRIBUTING.md) will guide you through the steps for getting started on the Elytron Web project and will go through how to format and submit your first PR.

For more details, check out our [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.