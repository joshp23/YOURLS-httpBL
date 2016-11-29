<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Database functions
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

// Create log table for this plugin when activated
yourls_add_action( 'activated_httpBL/plugin.php', 'httpBL_activated' );
function httpBL_activated() {
	global $ydb;

	// Log table
	$init_log = yourls_get_option('httpBL_init_log');
	if ($init_log === false) {
		// Create the init value
		yourls_add_option('httpBL_init_log', time());
		// Create the flag table
		$table_httpBL_log  = "CREATE TABLE IF NOT EXISTS httpBL_log (";
		$table_httpBL_log .= "timestamp timestamp NOT NULL default CURRENT_TIMESTAMP, ";
		$table_httpBL_log .= "action varchar(9) NOT NULL, ";
		$table_httpBL_log .= "ip varchar(15) NOT NULL, ";
		$table_httpBL_log .= "type varchar(50) NOT NULL, ";
		$table_httpBL_log .= "threat varchar(3) NOT NULL, ";
		$table_httpBL_log .= "activity varchar(255) NOT NULL, ";
		$table_httpBL_log .= "page varchar(20) NOT NULL, ";
		$table_httpBL_log .= "ua varchar(50) NOT NULL, ";
		$table_httpBL_log .= "PRIMARY KEY (timestamp) ";
		$table_httpBL_log .= ") ENGINE=MyISAM DEFAULT CHARSET=latin1;";
		$tables = $ydb->query($table_httpBL_log);

		yourls_update_option('httpBL_init_log', time());
		$init_log = yourls_get_option('httpBL_init_log');
		if ($init_log === false) {
			die("Unable to properly enable http:BL due an apparent problem with the log database.");
		}
	}
	
	// Whitelist table
	$init_wl = yourls_get_option('httpBL_init_wl');
	if ($init_wl === false) {
		// Create the init value
		yourls_add_option('httpBL_init_wl', time());
		// Create the flag table
		$table_httpBL_wl  = "CREATE TABLE IF NOT EXISTS httpBL_wl (";
		$table_httpBL_wl .= "timestamp timestamp NOT NULL default CURRENT_TIMESTAMP, ";
		$table_httpBL_wl .= "ip varchar(15) NOT NULL, ";
		$table_httpBL_wl .= "notes varchar(50) NOT NULL, ";
		$table_httpBL_wl .= "PRIMARY KEY (timestamp) ";
		$table_httpBL_wl .= ") ENGINE=MyISAM DEFAULT CHARSET=latin1;";
		$tables = $ydb->query($table_httpBL_wl);

		yourls_update_option('httpBL_init_wl', time());
		$init_wl = yourls_get_option('httpBL_init_wl');
		if ($init_wl === false) {
			die("Unable to properly enable http:BL due an apparent problem with the whitelist database.");
		}
	}
	// set the active option
	yourls_add_option('httpBL_active', true);
}
	
// Delete tables when plugin is deactivated
yourls_add_action('deactivated_httpBL/plugin.php', 'httpBL_deactivate');
function httpBL_deactivate() {
	// Logs Table
	$httpBL_table_drop_log = yourls_get_option('httpBL_table_drop_log');
	if ( $httpBL_table_drop_log !== "false" ) {
		global $ydb;
	
		$init_log = yourls_get_option('httpBL_init_log');
		if ($init_log !== false) {
			yourls_delete_option('httpBL_init_log');
			$ydb->query("DROP TABLE IF EXISTS `httpBL_log`");
		}
	}
	// Whitelist table
	$httpBL_table_drop_wl = yourls_get_option('httpBL_table_drop_wl');
	if ( $httpBL_table_drop_wl !== "false" ) {
		global $ydb;
	
		$init_wl = yourls_get_option('httpBL_init_wl');
		if ($init_wl !== false) {
			yourls_delete_option('httpBL_init_wl');
			$ydb->query("DROP TABLE IF EXISTS `httpBL_wl`");
		}
	}
	// delete the active option
	yourls_delete_option('httpBL_active');
}

// Flush the logs
function httpBL_flush_logs_do() {
	global $ydb;

	$init_log_1 = yourls_get_option('httpBL_init_log');

	if ($init_log_1 !== false) {
		$ydb->query("TRUNCATE TABLE `httpBL_log`");
		yourls_update_option('httpBL_init_log', time());
		$init_log_2 = yourls_get_option('httpBL_init_log');
		if ($init_log_2 == false || $init_log_1 == $init_log_2) {
			die("Unable to properly reset the log database. Contact your sys admin");
		}
	}
}
// Flush the whitelist
function httpBL_flush_wl_do() {
	global $ydb;

	$init_wl_1 = yourls_get_option('httpBL_init_wl');
	if ($init_wl_1 !== false) {
		$ydb->query("TRUNCATE TABLE `httpBL_wl`");
		yourls_update_option('httpBL_init_wl', time());
		$init_wl_2 = yourls_get_option('httpBL_init_wl');
		if ($init_wl_2 == false || $init_wl_1 == $init_wl_2) {
			die("Unable to properly reset the whitelist database. Contact your sys admin");
		}
	}
}
?>
