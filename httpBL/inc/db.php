<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Database functions
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

// Create tables for this plugin when activated
yourls_add_action( 'activated_httpBL/plugin.php', 'httpbl_activated' );
function httpbl_activated() {
	global $ydb;

	$init = yourls_get_option('httpbl_init');
	if ($init === false) {
		// Create the init value
		yourls_add_option('httpbl_init', time());
		// Create the flag table
		$table_httpbl  = "CREATE TABLE IF NOT EXISTS httpbl (";
		$table_httpbl .= "timestamp timestamp NOT NULL default CURRENT_TIMESTAMP, ";
		$table_httpbl .= "action varchar(9) NOT NULL, ";
		$table_httpbl .= "ip varchar(15) NOT NULL, ";
		$table_httpbl .= "type varchar(50) NOT NULL, ";
		$table_httpbl .= "threat varchar(3) NOT NULL, ";
		$table_httpbl .= "activity varchar(255) NOT NULL, ";
		$table_httpbl .= "page varchar(20) NOT NULL, ";
		$table_httpbl .= "ua varchar(50) NOT NULL, ";
		$table_httpbl .= "PRIMARY KEY (timestamp) ";
		$table_httpbl .= ") ENGINE=MyISAM DEFAULT CHARSET=latin1;";
		$tables = $ydb->query($table_httpbl);

		yourls_update_option('httpbl_init', time());
		$init = yourls_get_option('httpbl_init');
		if ($init === false) {
			die("Unable to properly enable http:BL due an apparent problem with the database.");
		}
	}
}

// Delete table when plugin is deactivated
yourls_add_action('deactivated_httpBL/plugin.php', 'httpbl_deactivate');
function httpbl_deactivate() {
	$httpbl_table_drop = yourls_get_option('httpbl_table_drop');
	if ( $httpbl_table_drop !== "false" ) {
		global $ydb;
	
		$init = yourls_get_option('httpbl_init');
		if ($init !== false) {
			yourls_delete_option('httpbl_init');
			$ydb->query("DROP TABLE IF EXISTS httpbl");
		}
	}
}

// Flush the Database
function httpbl_db_flush() {
	global $ydb;

	$table = 'httpbl';
	$init_1 = yourls_get_option('httpbl_init');

	if ($init_1 !== false) {
		$ydb->query("TRUNCATE TABLE `$table`");
		yourls_update_option('httpbl_init', time());
		$init_2 = yourls_get_option('httpbl_init');
		if ($init_2 === false || $init_1 == $init_2) {
			die("Unable to properly reset the database. Contact your sys admin");
		}
	}
}
?>
