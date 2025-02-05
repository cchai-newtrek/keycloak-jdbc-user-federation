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
        ResultSet rs = null;
        String query = constructQueryUserSQLStr();
        
        StopWatch watch = StopWatch.createStarted();
        try(
        	Connection conn = getConnection();
        	PreparedStatement pstmt = conn.prepareStatement(query)) {
        	
            pstmt.setString(1, user.getUsername());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst(CONFIG_PASSWORD_COL));
                logger.info("found user password with username:" +  user.getUsername());
            }
            
        } catch (SQLException ex) {
        	logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
        	logger.error("error in isValid", ex);
        } catch (Exception e) {
        	logger.error(e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                	logger.error(sqlEx.getMessage());
                } // ignore

                rs = null;
            }
            
        	watch.stop();
        	logger.debug("JdbcDBUserStorageProvider.isValid used " + watch.getDuration().toNanos() + " nanos.");
        }

        if (password == null)
            return false;

        return bCryptPasswordEncoder.matches(input.getChallengeResponse(), password);
    }

	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(realm, username);
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
        ResultSet rs = null;
        UserModel adapter = null;
        String query = constructQueryUserSQLStr();
        
        if(logger.isDebugEnabled()) {
        	MultivaluedHashMap<String, String> map = this.config.getConfig();
            Iterator<String> it = map.keySet().iterator();
            while(it.hasNext()){
            	String theKey = (String)it.next();
            	logger.debug("key:" + theKey + ", value:" + map.getFirst(theKey));
            }
        }
        
        StopWatch watch = StopWatch.createStarted();
        try(
        	Connection conn = getConnection();
        	PreparedStatement pstmt = conn.prepareStatement(query)) {
            
        	pstmt.setString(1, username);
            rs = pstmt.executeQuery();
            if (rs.next()) {
            	 String pword = rs.getString(this.config.getConfig().getFirst(CONFIG_PASSWORD_COL));
            	 if (pword != null) {
            		 //String id = rs.getString("ID");
                     adapter = createAdapter(realm, username);
                     
                 }
            }
            
        } catch (SQLException ex) {
        	logger.error("SQLState: " + ex.getSQLState() + ", VendorError:" + ex.getErrorCode());
        	logger.error("error in getUserByUsername", ex);
        } catch (Exception e) {
        	logger.error(e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                	logger.error(sqlEx.getMessage());
                } // ignore

                rs = null;
            }
            
        	watch.stop();
        	logger.debug("JdbcDBUserStorageProvider.getUserByUsername used " + watch.getDuration().toNanos() + " nanos.");
        }
        return adapter;
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

	private String constructQueryUserSQLStr() {
		return "SELECT ID, " + this.config.getConfig().getFirst(CONFIG_USERNAME_COL) + ", "
                + this.config.getConfig().getFirst(CONFIG_PASSWORD_COL) + " FROM "
                + this.config.getConfig().getFirst(CONFIG_TABLE) + " WHERE "
                + this.config.getConfig().getFirst(CONFIG_USERNAME_COL) + "=?;";
	}
	
	@Override
	public void close() {
		logger.debug("in JdbcDBUserStorageProvider.close()................");
	}

}
