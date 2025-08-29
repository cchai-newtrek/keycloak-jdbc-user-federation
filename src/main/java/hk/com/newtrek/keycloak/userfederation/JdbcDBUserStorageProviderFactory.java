package hk.com.newtrek.keycloak.userfederation;

import static hk.com.newtrek.keycloak.userfederation.CustomProperties.*;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import hk.com.newtrek.keycloak.userfederation.CustomProperties.DBType;

public final class JdbcDBUserStorageProviderFactory implements UserStorageProviderFactory<JdbcDBUserStorageProvider> {

	private static final Logger logger = Logger.getLogger(JdbcDBUserStorageProviderFactory.class);

	protected static final List<ProviderConfigProperty> configMetadata;

	public static final String PROVIDER_NAME = "jdbc-users";

	
	public static final String CONFIG_CONNECTION_POOL_LEAK_DETECTION_THRESHOLD = "connection-pool-leak-detection-threshold";
	
	// Regular expression for validating table and column names: alphanumeric and underscores only
	private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");

	static {
		configMetadata = ProviderConfigurationBuilder.create()
				.property().name(CONFIG_CONNECTION_URL).type(ProviderConfigProperty.STRING_TYPE).label("JDBC Connection URL")
					.helpText("JDBC Connection URL (should contain the database login and password)").add()
				.property().name(CONFIG_TABLE).type(ProviderConfigProperty.STRING_TYPE).label("Table name that storing users")
					.defaultValue("user").helpText("Table where users are stored").add()
				.property().name(CONFIG_USERNAME_COL).type(ProviderConfigProperty.STRING_TYPE).label("Username Column")
					.defaultValue("username").helpText("Column name that holds the usernames").add()
				.property().name(CONFIG_PASSWORD_COL).type(ProviderConfigProperty.STRING_TYPE).label("Password Column")
					.defaultValue("password").helpText("Column name that holds the passwords").add()

				//use connection pool or not
				.property().name(CONFIG_USE_CONNECTION_POOL).type(ProviderConfigProperty.BOOLEAN_TYPE).label("Use Connection Pool?")
					.defaultValue(true).helpText("Use connection pool or not? If not will create DB connection every time need access to user database (default is true).").add()
					
				//connection pool parameters tuning
				.property().name(CONFIG_CONNECTION_POOL_NAME).type(ProviderConfigProperty.STRING_TYPE).label("Connection Pool Name")
					.defaultValue("KeycloakJDBCPool").helpText("Connection pool name").add()
				.property().name(CONFIG_CONNECTION_POOL_MAX_POOL_SIZE).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Max. Pool Size")
					.defaultValue(30).helpText("Connection pool maximum pool size (default 30)").add()
				.property().name(CONFIG_CONNECTION_POOL_MIN_IDLE).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Min. Idle Connection")
					.defaultValue(5).helpText("Connection pool minimum idle connection (default 5)").add()
				.property().name(CONFIG_CONNECTION_POOL_MAX_LIEF_TIME).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Max. Life Time")
					.defaultValue(1800000).helpText("Connection pool maximum life time (default 1800000 ms (30 mins)").add()
				.property().name(CONFIG_CONNECTION_POOL_CONNECTION_TIMEOUT).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Connection Timeout")
					.defaultValue(30000).helpText("Connection pool connection timeout (default 30000 ms (30 seconds)").add()
				.property().name(CONFIG_CONNECTION_POOL_IDLE_TIMEOUT).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Idle Timeout")
					.defaultValue(600000).helpText("Connection pool idle timeout (default 600000 ms (10 mins)").add()
				.property().name(CONFIG_CONNECTION_POOL_LEAK_DETECTION_THRESHOLD).type(ProviderConfigProperty.INTEGER_TYPE).label("Connection Pool Leak Detection Threshold")
					.defaultValue(0).helpText("Connection pool leak detection threshold (default 0 ms (by default is disabled, minimum value is 2000 ms)").add()
				.build();
	}

	private HikariDataSource dataSource; // HikariCP connection pool

	
	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configMetadata;
	}

	@Override
	public String getId() {
		return PROVIDER_NAME;
	}

	protected boolean isValidTableNameOrColumnName(final String inValue, final DBType dbType) {
		if (inValue == null || dbType == null) {
			return false;
		}
		
		String[] allowedQuotes = dbType.getAllowedQuotes();
		
		String value = inValue.trim();
		
		if(allowedQuotes != null && allowedQuotes.length > 0) {
			if(Arrays.stream(allowedQuotes).anyMatch(quote -> inValue.startsWith(quote))) {
				value = value.substring(1);
			}
			
			if(Arrays.stream(allowedQuotes).anyMatch(quote -> inValue.endsWith(quote))) {
				value = StringUtils.chop(value);
			}
		}
		
		return IDENTIFIER_PATTERN.matcher(value).matches();
	}
	
	@Override
	public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
			throws ComponentValidationException {
		String url = config.getConfig().getFirst(CONFIG_CONNECTION_URL);
		if (url == null)
			throw new ComponentValidationException("connection URL not present");
		
		DBType dbType = DBType.getDbType(url);
		
		//checking for table name and column name values to avoid SQL injection
		String tableName = StringUtils.defaultString(config.getConfig().getFirst(CONFIG_TABLE)).trim();
		String usernameCol = StringUtils.defaultString(config.getConfig().getFirst(CONFIG_USERNAME_COL)).trim();
		String passwordCol = StringUtils.defaultString(config.getConfig().getFirst(CONFIG_PASSWORD_COL)).trim();

		final String tableNameColNameErrMsg = "must contain only letters, numbers, underscores"
										+ ((dbType.getAllowedQuotes() != null && dbType.getAllowedQuotes().length > 0)?
											" and DB quotes: " + String.join(",", dbType.getAllowedQuotes()): ""
										);
		if (!isValidTableNameOrColumnName(tableName, dbType)) {
			throw new ComponentValidationException("Invalid table name: " + tableNameColNameErrMsg);
		}
		
		if (!isValidTableNameOrColumnName(usernameCol, dbType)) {
			throw new ComponentValidationException("Invalid username column name: " + tableNameColNameErrMsg);
		}

		if (!isValidTableNameOrColumnName(passwordCol, dbType)) {
			throw new ComponentValidationException("Invalid password column name: " + tableNameColNameErrMsg);
		}
		
		try {
			Class.forName(dbType.getJdbcDriver().getCanonicalName());
		} catch (Exception e) {
			 logger.error(e.getMessage());
		}
		
		boolean isValid = false;
		try(Connection conn = DriverManager.getConnection(url)) {
			//conn.isValid timeout in seconds
			conn.isValid(10);
			isValid = true;
		} catch (SQLException ex) {
			logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
			logger.error("error in validateConfiguration", ex);
			throw new ComponentValidationException(ex.getMessage());
		} catch (Exception e) {
			logger.error(e.getMessage());
			throw new RuntimeException(e.getMessage());
		}

		if(isValid) {
			//reset the dataSource as the configuration is changed
			closeDataSource();
			initDataSource(config);
		}
	}

	@Override
	public JdbcDBUserStorageProvider create(KeycloakSession session, ComponentModel config) {
		if(dataSource == null) {
			initDataSource(config);
		}
		
		return new JdbcDBUserStorageProvider(session, config, dataSource);
	}
	
	private void closeDataSource() {
		if (dataSource != null) {
			logger.info("Closing HikariCP pool:"+dataSource.getPoolName()+" .........");
			dataSource.close(); // Close the HikariCP pool
		}
		
		dataSource = null;
	}

	private void initDataSource(ComponentModel config) {
		
		final String jdbcUrl = config.getConfig().getFirst(CONFIG_CONNECTION_URL);
		DBType dbType = DBType.getDbType(jdbcUrl);

		// HikariCP Configuration
		HikariConfig hikariConfig = new HikariConfig();
		hikariConfig.setJdbcUrl(jdbcUrl);
		hikariConfig.setDriverClassName(dbType.getJdbcDriver().getCanonicalName());
		
		// Pool Size Tuning (Important!)
		hikariConfig.setMaximumPoolSize(Integer.parseInt(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_MAX_POOL_SIZE)));
		hikariConfig.setMinimumIdle(Integer.parseInt(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_MIN_IDLE)));
		hikariConfig.setMaxLifetime(Long.parseLong(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_MAX_LIEF_TIME)));
		hikariConfig.setConnectionTimeout(Long.parseLong(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_CONNECTION_TIMEOUT)));
		hikariConfig.setIdleTimeout(Long.parseLong(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_IDLE_TIMEOUT)));
		hikariConfig.setLeakDetectionThreshold(Long.parseLong(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_LEAK_DETECTION_THRESHOLD)));

		// Additional HikariCP settings (optional, but recommended)
		hikariConfig.setPoolName(config.getConfig().getFirst(CONFIG_CONNECTION_POOL_NAME)); // Give your pool a name
		hikariConfig.setAutoCommit(false); // set auto commit to true may not be a good idea
		hikariConfig.setConnectionTestQuery(dbType.getTestSql()); // Test connection on borrow

		try {
			dataSource = new HikariDataSource(hikariConfig);
		} catch (Exception e) {
			logger.error("Error initializing HikariCP data source" + e);
			throw new RuntimeException("Error initializing JDBC connection pool", e); // Or handle differently
		}
	}
	
	@Override
	public void init(Scope config) {
		UserStorageProviderFactory.super.init(config);
		logger.info("in JdbcDBUserStorageProviderFactory.init() .........");
	}

	@Override
	public void close() {
		UserStorageProviderFactory.super.close();
		closeDataSource();
	}
	
	

}