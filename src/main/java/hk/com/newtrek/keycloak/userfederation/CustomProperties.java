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
	
	public static final String getJdbcDriver(final String jdbcUrl) {
		if(jdbcUrl == null) return null;
		
		String lowerJdbcUrl = jdbcUrl.trim().toLowerCase(); 
		
		if (lowerJdbcUrl.startsWith("jdbc:mariadb:")) {
			//MariaDB
			return "org.mariadb.jdbc.Driver";
		} else if (lowerJdbcUrl.startsWith("jdbc:mysql:")) {
			//MySQL
			return "com.mysql.cj.jdbc.Driver";
		} else if (lowerJdbcUrl.startsWith("jdbc:sqlserver:")) {
			//SQL Server
			return "com.microsoft.sqlserver.jdbc.SQLServerDriver";
		} else if (lowerJdbcUrl.startsWith("jdbc:postgresql:")) {
			//Postgresql
			return "org.postgresql.Driver";
/**
 * to be verified for the China DBMS
 */
//		} else if (lowerJdbcUrl.startsWith("jdbc:gaussdb:")) {
//			//GaussDB
//			return "com.huawei.gaussdb.jdbc.Driver";
//		} else if (lowerJdbcUrl.startsWith("jdbc:opengauss:")) {
//			//Open GaussDB
//			return "com.huawei.opengauss.jdbc.Driver";
//		} else if (lowerJdbcUrl.startsWith("jdbc:oceanbase:")) {
//			//OceanBase
//			return "com.alipay.oceanbase.jdbc.Driver";
		} else if (lowerJdbcUrl.startsWith("jdbc:hsqldb:")) {
			//hsql
			return "org.hsqldb.jdbc.JDBCDriver";
		} else if (lowerJdbcUrl.startsWith("jdbc:oracle:")) {
			//Oracle (Most likely not to be used in future for government project)
			return "oracle.jdbc.OracleDriver";
		} else {
			return null;
		}
	}
}
