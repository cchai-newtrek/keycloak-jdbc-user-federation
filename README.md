# keycloak-jdbc-user-federation

Keycloak user federation extension to connect to database containing users through jdbc. 

Useful links:

- [reference](https://github.com/kyrcha/keycloak-mysql-user-federation)

- [official Keycloak guide](https://www.keycloak.org/docs/latest/server_development/index.html#_user-storage-spi)

## Installation 

Project requirement:

- JDK version: 21 (as OpenJDK 17 support is deprecated after Keycloak 25.0.0)
- Maven 3.8+
- Keycloak version: 26.1.0

## Deployment Step

1. Build by `mvn clean package`
2. The jar keycloak-jdbc-user-storage-[version].jar and the dependency jars will be generated in target/ folder

---

We should use the SIT Keycloak server. Therefore, below setup steps are just for reference only.

1. Copy all the jars (the artifact and all it's dependency jars) into *KEYCLOAK_HOME/providers* folder. 
2. Update the keycloak configs in *KEYCLOAK_HOME/conf/keycloak.conf*, such as database config, port, log file path, etc
3. Check if the Java path is correct in *KEYCLOAK_HOME/bin/kc.bat*
4. Install the custom jar (and it's dependency jars) by `bin\kc.bat build`
5. Run the keycloak by `bin\kc.bat start-dev` (dev) or `bin\kc.bat start`

---

After installed the custom jar, go to Keycloak admin page and select User federation page.

Add the following properties:

- The database connection URL
- The table containing the user data (sql server may need to use square bracket, e.g. [user] instead of user)
- The column name of username
- The column name of password

Save the config.
