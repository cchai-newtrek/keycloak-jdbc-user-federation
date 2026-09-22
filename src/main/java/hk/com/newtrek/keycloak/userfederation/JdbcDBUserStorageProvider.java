package hk.com.newtrek.keycloak.userfederation;

import static hk.com.newtrek.keycloak.userfederation.CustomProperties.*;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Iterator;

import org.apache.commons.lang3.time.StopWatch;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.storage.user.UserLookupProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.zaxxer.hikari.HikariDataSource;

import hk.com.newtrek.keycloak.userfederation.CustomProperties.DBType;

public final class JdbcDBUserStorageProvider
		implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

	protected KeycloakSession session;
	protected ComponentModel config;
	protected BCryptPasswordEncoder bCryptPasswordEncoder;
	protected HikariDataSource dataSource;
	
	private static final Logger logger = Logger.getLogger(JdbcDBUserStorageProvider.class);

	public JdbcDBUserStorageProvider(KeycloakSession session, ComponentModel config, HikariDataSource dataSource) {
		this.session = session;
		this.config = config;
		bCryptPasswordEncoder = new BCryptPasswordEncoder();
		this.dataSource = dataSource;
	}

	protected UserModel createAdapter(RealmModel realm, String username) {
		return new AbstractUserAdapterFederatedStorage(session, realm, config) {
			@Override
			public String getUsername() {
				return username;
			}

			@Override
			public void setUsername(String username) {
				//do nothing
			}

		};
	}
	
	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		return supportsCredentialType(credentialType);
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		return credentialType.equals(PasswordCredentialModel.TYPE);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		if (!supportsCredentialType(input.getType()))
			return false;
		
		String password = null;
		
		boolean isUserFound = false;
		
		final boolean skipPasswordChecking = Boolean.parseBoolean(this.config.getConfig().getFirst(CONFIG_SKIP_PASSWORD_CHECKING));
		final String passwordCol = skipPasswordChecking? null : this.config.getConfig().getFirst(CONFIG_PASSWORD_COL);

		/**
		 * to minimize the operation after open and before the close of the DB connection
		 * so anything not need the DB connection should do before the open of DB connection or after the close of DB connection
		 * as DB connection should be released ASAP, do not do redundant operation in between DB connection, as it will block others to access the DB
		 */
		StopWatch watch = StopWatch.createStarted();
		try (Connection conn = getConnection();
				PreparedStatement pStmt = createGetUserStatement(conn, user.getUsername());
				ResultSet rs = pStmt.executeQuery();
		) {
			if (rs.next()) {
				isUserFound = true;
				if(!skipPasswordChecking || passwordCol != null) {
					password = rs.getString(passwordCol);
				}
			}
		} catch (SQLException ex) {
			logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
			logger.error("error in isValid", ex);
		} catch (Exception e) {
			logger.error(e);
		} finally {
		}
		
		watch.stop();
		logger.debug("JdbcDBUserStorageProvider.isValid used " + watch.getDuration().toNanos() + " nanos.");

		if(!isUserFound) {
			logger.warn("!!! Username: " +  user.getUsername() + " not found............");
			return false;
		}
		
		if (!skipPasswordChecking && password == null) {
			logger.warn("!!! Username: " +  user.getUsername() + ", the password is null............");
			return false;
		}
		
		final boolean isPasswordMatch = skipPasswordChecking? true : bCryptPasswordEncoder.matches(input.getChallengeResponse(), password);
		if(isPasswordMatch) {
			logger.info("Username: " +  user.getUsername() + " login successfully!");
		} else {
			logger.warn("!!! Username: " +  user.getUsername() + ", the password is not matched............");
		}
		
		return isPasswordMatch;
	}

	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		StorageId storageId = new StorageId(id);
		String username = storageId.getExternalId();
		return getUserByUsername(realm, username);
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		UserModel adapter = null;
		if (logger.isDebugEnabled()) {
			MultivaluedHashMap<String, String> map = this.config.getConfig();
			Iterator<String> it = map.keySet().iterator();
			while (it.hasNext()) {
				String theKey = (String) it.next();
				logger.debug("key:" + theKey + ", value:" + map.getFirst(theKey));
			}
		}

		String pword = null;
		
		/**
		 * to minimize the operation after open and before the close of the DB connection 
		 * so anything not need the DB connection should do before the open of DB connection or after the close of DB connection
		 * as DB connection should be released ASAP, do not do redundant operation in between DB connection, as it will block others to access the DB
		 */
		final boolean skipPasswordChecking = Boolean.parseBoolean(config.getConfig().getFirst(CONFIG_SKIP_PASSWORD_CHECKING));
		final String passwordCol = skipPasswordChecking? null : this.config.getConfig().getFirst(CONFIG_PASSWORD_COL);
		
		StopWatch watch = StopWatch.createStarted();
		try (Connection conn = getConnection();
				PreparedStatement pStmt = createGetUserStatement(conn, username);
				ResultSet rs = pStmt.executeQuery();
		) {
			if (rs.next() && passwordCol != null) {
				pword = rs.getString(passwordCol);
			}
		} catch (SQLException ex) {
			logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
			logger.error("error in getUserByUsername", ex);
		} catch (Exception e) {
			logger.error(e);
		} finally {
		}
		watch.stop();
		logger.debug("JdbcDBUserStorageProvider.getUserByUsername used " + watch.getDuration().toNanos() + " nanos.");

		if (skipPasswordChecking || pword != null) {
			adapter = createAdapter(realm, username);
		}

		return adapter;
	}

	private PreparedStatement createGetUserStatement(Connection conn, String username) throws Exception {
		String query = constructQueryUserSQLStr(conn);
		PreparedStatement pStmt = conn.prepareStatement(query);
		try {
			pStmt.setString(1, username);
			return pStmt;
		} catch (SQLException ex) {
			logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
			logger.error("error in getUserByUsername", ex);
			throw ex;
		} catch (Exception e) {
			logger.error(e);
			throw e;
		} finally {
		}
	}
	
	private Connection getConnection() throws ClassNotFoundException, SQLException {
		final boolean useConnectionPool = Boolean.parseBoolean(config.getConfig().getFirst(CONFIG_USE_CONNECTION_POOL));
		
		if(useConnectionPool) {
			logger.debug("...... use connection pool .......");
			return dataSource.getConnection();
		} else {
			logger.debug("...... NOT using connection pool (use DriverManager.getConnection(url)) .......");
			final String url = config.getConfig().getFirst(CONFIG_CONNECTION_URL);
			DBType dbType = DBType.getDbType(url);
			
			Class.forName(dbType.getJdbcDriver().getCanonicalName());
			return DriverManager.getConnection(url);
		}
	}
	
	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		return null;
	}

	private String constructQueryUserSQLStr(final Connection conn) {
		final boolean skipPasswordChecking = Boolean.parseBoolean(config.getConfig().getFirst(CONFIG_SKIP_PASSWORD_CHECKING));
		final String tableName = validateAndQuoteIdentifier(config.getConfig().getFirst(CONFIG_TABLE), "Table name", conn);
		final String usernameCol = validateAndQuoteIdentifier(config.getConfig().getFirst(CONFIG_USERNAME_COL), "Username column name", conn);

		String passwordCol = null;
		if (!skipPasswordChecking) {
			passwordCol = validateAndQuoteIdentifier(config.getConfig().getFirst(CONFIG_PASSWORD_COL), "Password column name", conn);
		}

		StringBuilder sql = new StringBuilder();
		sql.append("SELECT ID, ").append(usernameCol);
		if (passwordCol != null) {
			sql.append(", ").append(passwordCol);
		}
		sql.append(" FROM ").append(tableName).append(" WHERE ").append(usernameCol).append(" = ?;");
		
		final String constructedSQL = sql.toString();
		logger.debug("Constructed SQL query: " + constructedSQL);
		
		return constructedSQL;
	}

	private String validateAndQuoteIdentifier(String value, String label, Connection connection) {
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException(label + " must not be empty");
		}

		// Security layer: strict whitelist
		if (!value.matches("^[a-zA-Z][a-zA-Z0-9_]*$")) {
			throw new IllegalArgumentException(label + " contains invalid characters: '" + value
					+ "'. Only letters, digits, and underscores are allowed.");
		}

		// Compatibility layer: database-specific quoting
		try {
			String quote = connection.getMetaData().getIdentifierQuoteString();
			String closeQuote = quote.equals("[") ? "]" : quote; // SQL Server special case
			return quote + value + closeQuote;
		} catch (SQLException e) {
			// Fallback to standard double quotes if metadata unavailable
			return "\"" + value + "\"";
		}
	}
	
	@Override
	public void close() {
		logger.debug("in JdbcDBUserStorageProvider.close()................");
	}

}
