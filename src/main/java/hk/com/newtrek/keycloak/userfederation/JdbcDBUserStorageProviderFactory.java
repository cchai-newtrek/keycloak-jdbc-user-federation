package hk.com.newtrek.keycloak.userfederation;

import static hk.com.newtrek.keycloak.userfederation.CustomProperties.*;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

public final class JdbcDBUserStorageProviderFactory implements UserStorageProviderFactory<JdbcDBUserStorageProvider> {

    private static final Logger logger = Logger.getLogger(JdbcDBUserStorageProviderFactory.class);

    protected static final List<ProviderConfigProperty> configMetadata;

    public static final String PROVIDER_NAME = "jdbc-users";

    static {
        configMetadata = ProviderConfigurationBuilder.create()
        		.property().name(CONFIG_CONNECTION_URL).type(ProviderConfigProperty.STRING_TYPE).label("JDBC Connection URL")
                	.defaultValue("jdbcurl").helpText("JDBC Connection URL").add()
                .property().name(CONFIG_TABLE).type(ProviderConfigProperty.STRING_TYPE).label("Table name that storing users")
                	.defaultValue("user").helpText("Table where users are stored").add()
                .property().name(CONFIG_USERNAME_COL).type(ProviderConfigProperty.STRING_TYPE).label("Username Column")
                	.defaultValue("username").helpText("Column name that holds the usernames").add()
                .property().name(CONFIG_PASSWORD_COL).type(ProviderConfigProperty.STRING_TYPE).label("Password Column")
                	.defaultValue("password").helpText("Column name that holds the passwords").add()
                .build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
        String url = config.getConfig().getFirst(CONFIG_CONNECTION_URL);
        if (url == null)
            throw new ComponentValidationException("connection URL not present");
          
        try {
			Class.forName(getJdbcDriver(url));
		} catch (ClassNotFoundException e) {
			 logger.error("invalid JDBC driver: " + e.getMessage());
		}
        
        try(Connection conn = DriverManager.getConnection(url)) {
            conn.isValid(1000);
            
        } catch (SQLException ex) {
        	logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
        	logger.error("error in validateConfiguration", ex);
            throw new ComponentValidationException(ex.getMessage());
        }
    }

    @Override
    public JdbcDBUserStorageProvider create(KeycloakSession session, ComponentModel config) {
    	return new JdbcDBUserStorageProvider(session, config);
    }

}