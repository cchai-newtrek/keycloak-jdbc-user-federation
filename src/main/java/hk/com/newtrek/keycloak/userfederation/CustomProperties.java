package hk.com.newtrek.keycloak.userfederation;

import java.util.Arrays;

public final class CustomProperties {
	/*
	 *  Predefined property once defined and saved, the name cannot be changed directly.
	 *  If you changed the name here, you need to save the config again to create the new property with new name.
	 *  The saved properties seems to be stored in database, but there is no simple way to find out and modify.
	 */
	public static final String CONFIG_CONNECTION_URL = "connection-url";
	public static final String CONFIG_TABLE = "table";
	public static final String CONFIG_USERNAME_COL = "username-col";
	public static final String CONFIG_PASSWORD_COL = "password-col";
	
	public static final String CONFIG_USE_CONNECTION_POOL = "use-connection-pool";
	/*
	 * connection pool parameters
	 */
	public static final String CONFIG_CONNECTION_POOL_MAX_POOL_SIZE = "connection-pool-max-pool-size";
	public static final String CONFIG_CONNECTION_POOL_MIN_IDLE = "connection-pool-min-idle";
	public static final String CONFIG_CONNECTION_POOL_MAX_LIEF_TIME = "connection-pool-max-life-time";
	public static final String CONFIG_CONNECTION_POOL_CONNECTION_TIMEOUT = "connection-pool-connection-timeout";
	public static final String CONFIG_CONNECTION_POOL_IDLE_TIMEOUT = "connection-pool-idle-timeout";
	public static final String CONFIG_CONNECTION_POOL_LEAK_DETECTION_THRESHOLD = "connection-pool-leak-detection-threshold";
	
	public enum DBType {
		MARIADB("jdbc:mariadb:", org.mariadb.jdbc.Driver.class, "SELECT 1")
		, MYSQL("jdbc:mysql:", com.mysql.cj.jdbc.Driver.class, "SELECT 1")
		, SQLSERVER("jdbc:sqlserver:", com.microsoft.sqlserver.jdbc.SQLServerDriver.class, "SELECT 1")
		, POSTGRESQL("jdbc:postgresql:", org.postgresql.Driver.class, "SELECT 1")
		, HSQL("jdbc:hsqldb:", org.hsqldb.jdbc.JDBCDriver.class, "SELECT 1 FROM INFORMATION_SCHEMA.SYSTEM_USERS")
		, ORACLE("jdbc:oracle:", oracle.jdbc.OracleDriver.class, "SELECT 1 FROM DUAL")
		
		/**
		 * China DBMS to be verified
		 */
//		, GAUSSDB("jdbc:gaussdb:", com.huawei.gaussdb.jdbc.Driver.class, "SELECT 1 FROM DUAL")
//		, OPENGAUSS("jdbc:opengauss:", com.huawei.opengauss.jdbc.Driver.class, "SELECT 1 FROM DUAL")
//		, OCEANBASE("jdbc:oceanbase:", com.alipay.oceanbase.jdbc.Driver, "SELECT 1")
		;
		
		private DBType(final String jdbcUrlPrefix, final Class<?> jdbcDriver, final String testSql) {
			this.jdbcUrlPrefix = jdbcUrlPrefix;
			this.jdbcDriver = jdbcDriver;
			this.testSql = testSql;
		}

		private String jdbcUrlPrefix;
		private Class<?> jdbcDriver;
		private String testSql;
		
		public String getJdbcUrlPrefix() {
			return jdbcUrlPrefix;
		}

		public Class<?> getJdbcDriver() {
			return jdbcDriver;
		}

		public String getTestSql() {
			return testSql;
		}

		public static DBType getDbType(final String jdbcUrl) {
			if(jdbcUrl == null) throw new NullPointerException("jdbcUrl is null");
			
			return Arrays.stream(DBType.values())
					.filter(dbType -> jdbcUrl.trim().toLowerCase().startsWith(dbType.getJdbcUrlPrefix()))
					.findFirst()
					.orElse(null)
					;
		}
	}

}
