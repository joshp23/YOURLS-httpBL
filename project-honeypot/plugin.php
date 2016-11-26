<?php
/**
Plugin Name: Project Honeypot http:BL
Plugin URI: https://github.com/joshp23/YOURLS-Project-Honeypot
Description: An implementation of Project Honeypot's http:BL for YOURLS
Version: 0.1
Author: Josh Panter
Author URI: https://unfettered.net
**/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

require ('inc/db.php');
require ('inc/sys.php');

// check for "is human/not a bot" cookie
httpbl_human_check();


// Register admin forms
yourls_add_action( 'plugins_loaded', 'httpbl_add_pages' );
function httpbl_add_pages() {
        yourls_register_plugin_page( 'httpbl', 'Project Honeypot http:BL', 'httpbl_do_page' );
}
// Admin page 0 - structure
function httpbl_do_page() {

	// CHECK if CORE options form was submitted
	httpbl_update_op_core();
	
	// Retreive CORE settings & set appropriate values
	
	// API Key
	$httpbl_api_key = yourls_get_option( 'httpbl_api_key' );
	
	// Custom http:BL block page
	$httpbl_cstm_block_tgl = yourls_get_option( 'httpbl_cstm_block_tgl' );
	if ($httpbl_cstm_block_tgl == "true") {
		$url_chk = 'checked';
	} else {
		$url_chk = null;
	}
	$httpbl_cstm_block = yourls_get_option( 'httpbl_cstm_block' );
	
	// Preserve logs on deactivate?
	$httpbl_table_drop = yourls_get_option( 'httpbl_table_drop' );
	if ($httpbl_table_drop !== "false") {		// default = true
		$drop_chk = 'checked';
	} else {
		$drop_chk = null;
	}
	
	// Log Blocked visitors?		
	$httpbl_log_blocked = yourls_get_option( 'httpbl_log_blocked' );
	if ($httpbl_log_blocked == "true") {
		$lb_chk = 'checked';
	} else {
		$lb_chk = null;
	}
	
	// Log Unblocked visitors?		
	$httpbl_log_unblocked = yourls_get_option( 'httpbl_log_unblocked' );
	if ($httpbl_log_unblocked == "true") {
		$lub_chk = 'checked';
	} else {
		$lub_chk = null;
	}
	
	// Show log tab?
	if ( ($httpbl_log_blocked == "true") || ($httpbl_log_unblocked == "true") ) {
		$log_vis = 'inline';
	} else { 
		$log_vis = 'none';
	}
	
	// CHECK if the DATABASE FLUSH form was submitted
	httpbl_flush_logs();

	// Create nonce
	$nonce = yourls_create_nonce( 'httpbl' );

	// Main interface html
	$vars = array();
		$vars['httpbl_api_key'] = $httpbl_api_key;
		$vars['httpbl_cstm_block_tgl'] = $httpbl_cstm_block_tgl;
		$vars['httpbl_cstm_block'] = $httpbl_cstm_block;
		$vars['httpbl_table_drop'] = $httpbl_table_drop;
		$vars['httpbl_log_blocked'] = $httpbl_log_blocked;
		$vars['httpbl_log_unblocked'] = $httpbl_log_unblocked;
		$vars['url_chk'] = $url_chk;
		$vars['drop_chk'] = $drop_chk;
		$vars['lb_chk'] = $lb_chk;
		$vars['lub_chk'] = $lub_chk;
		$vars['log_vis'] = $log_vis;
		
		$vars['nonce'] = $nonce;

	$opt_view = file_get_contents( dirname( __FILE__ ) . '/inc/opt.php', NULL, NULL, 212);
	// Replace all %stuff% in opt with variable $stuff
	$opt_view = preg_replace_callback( '/%([^%]+)?%/', function( $match ) use( $vars ) { return $vars[ $match[1] ]; }, $opt_view );

	echo $opt_view;

	httpbl_log_view();
}
// Display page 0.1 - log view
function httpbl_log_view() {
	// should we bother with this data, has the "nuke" option been set?"
	$log_blocked = yourls_get_option( 'httpbl_log_blocked' );
	$log_unblocked = yourls_get_option( 'httpbl_log_unblocked' );
	if ( ($log_blocked == "true") || ($log_unblocked == "true") ) {
		// Log are checked ~ this picks up where opt.0.php leaves off.
		global $ydb;
		echo <<<HTML
			<h3>http:BL Log Table</h3>
			<p>These values are from the Project Honeypot catagorization scheme. More information on that can be found <a href="https://www.projecthoneypot.org/httpbl_api.php" target="_blank">here</a>.</p>
				<table id="main_table" class="tblSorter" border="1" cellpadding="5" style="border-collapse: collapse">
					<thead>
						<tr>
							<th>IP Address</th>
							<th>Action</th>
							<th>Type</th>
							<th>Score</th>
							<th>Activity</th>
							<th>Time of Incident</th>
						</tr>
					</thead>
					<tbody>
HTML;
		
		// populate table rows with flag data if there is any
		$table = 'httpbl';
		$logs = $ydb->get_results("SELECT * FROM `$table` ORDER BY timestamp DESC");
		$found_rows = false;
		if($logs) {
			$found_rows = true;
			foreach( $logs as $log ) {
				$ip = $log->ip;
				$timestamp = strtotime($log->timestamp);
				$action = $log->action;
				$type = $log->type;
				$threat = $log->threat;
				$activity = $log->activity;
				$date = date( 'M d, Y H:i', $timestamp);
				// print if there is any data
				echo <<<HTML
						<tr>
							<td>$ip</td>
							<td>$action</td>
							<td>$type</td>
							<td>$threat</td>
							<td>$activity</td>
							<td>$date</td>
						</tr>
HTML;
			}
		}
				echo "</tbody>\n";
			echo "</table>\n";
	}
	// close log div and the rest of the settings page
			echo "</div>\n";
		echo "</div>\n";
		echo "</div>\n";
	echo "</div>\n";
}
?>
