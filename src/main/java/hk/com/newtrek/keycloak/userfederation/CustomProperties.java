package hk.com.newtrek.keycloak.userfederation;

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
		MARIADB, MYSQL, SQLSERVER, POSTGRESQL, HSQL, ORACLE
		
		/**
		 * China DBMS
		 */
		, GAUSSDB, OPENGAUSS, OCEANBASE;
	}
	
	public static final class DBInfo {
		private DBType dbType;
		private String jdbcDriver;
		private String testSql;
		
		public DBInfo(final String jdbcUrl) {
			if(jdbcUrl == null) {
				throw new NullPointerException("jdbcUrl is null");
			}
			
			String lowerJdbcUrl = jdbcUrl.trim().toLowerCase();
			
			if (lowerJdbcUrl.startsWith("jdbc:mariadb:")) {
				//MariaDB
				this.dbType = DBType.MARIADB;
				this.jdbcDriver = "org.mariadb.jdbc.Driver";
				this.testSql = "SELECT 1";
			} else if (lowerJdbcUrl.startsWith("jdbc:mysql:")) {
				//MySQL
				this.dbType = DBType.MYSQL;
				this.jdbcDriver = "com.mysql.cj.jdbc.Driver";
				this.testSql = "SELECT 1";
			} else if (lowerJdbcUrl.startsWith("jdbc:sqlserver:")) {
				//SQL Server
				this.dbType = DBType.SQLSERVER;
				this.jdbcDriver = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
				this.testSql = "SELECT 1";
			} else if (lowerJdbcUrl.startsWith("jdbc:postgresql:")) {
				//Postgresql
				this.dbType = DBType.POSTGRESQL;
				this.jdbcDriver = "org.postgresql.Driver";
				this.testSql = "SELECT 1";
			} else if (lowerJdbcUrl.startsWith("jdbc:hsqldb:")) {
				//hsql
				this.dbType = DBType.HSQL;
				this.jdbcDriver = "org.hsqldb.jdbc.JDBCDriver";
				this.testSql = "SELECT 1 FROM INFORMATION_SCHEMA.SYSTEM_USERS";
			} else if (lowerJdbcUrl.startsWith("jdbc:oracle:")) {
				//Oracle (Most likely not to be used in future for government project)
				this.dbType = DBType.ORACLE;
				this.jdbcDriver = "oracle.jdbc.OracleDriver";
				this.testSql = "SELECT 1 FROM DUAL";
				/**
				 * to be verified for the China DBMS
				 */
//			} else if (lowerJdbcUrl.startsWith("jdbc:gaussdb:")) {
//				//GaussDB
//				this.dbType = DBType.GAUSSDB;
//				this.jdbcDriver = "com.huawei.gaussdb.jdbc.Driver";
//				this.testSql = "SELECT 1 FROM DUAL";
//			} else if (lowerJdbcUrl.startsWith("jdbc:opengauss:")) {
//				//Open GaussDB
//				this.dbType = DBType.OPENGAUSS;
//				this.jdbcDriver = "com.huawei.opengauss.jdbc.Driver";
//				this.testSql = "SELECT 1 FROM DUAL";
//			} else if (lowerJdbcUrl.startsWith("jdbc:oceanbase:")) {
//				//OceanBase
//				this.dbType = DBType.OCEANBASE;
//				this.jdbcDriver = "com.alipay.oceanbase.jdbc.Driver";
//				this.testSql = "SELECT 1";
			} else {
				throw new IllegalArgumentException("Unsupported jdbcUrl: " + jdbcUrl);
			}
		}

		public DBType getDbType() {
			return dbType;
		}

		public String getJdbcDriver() {
			return jdbcDriver;
		}

		public String getTestSql() {
			return testSql;
		}
		
	}
}
