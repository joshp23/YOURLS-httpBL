<?php
/**
Plugin Name: HTTP:BL
Plugin URI: https://github.com/joshp23/YOURLS-httpBL
Description: An implementation of Project Honeypot's http:BL for YOURLS
Version: 1.0
Author: Josh Panter
Author URI: https://unfettered.net
**/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

require ('inc/db.php');
require ('inc/sys.php');
require ('inc/wl.php');

// check for cookie & whitelist
$is = yourls_get_option('httpBL_active');
if ( $is == true) httpBL_human_check(); 


// Register admin forms
yourls_add_action( 'plugins_loaded', 'httpBL_add_pages' );
function httpBL_add_pages() {
        yourls_register_plugin_page( 'httpBL', 'HTTP:BL', 'httpBL_do_page' );
}
// Admin page - structure
function httpBL_do_page() {

	// CHECK if CORE options form was submitted
	httpBL_update_op_core();
	
	// Retreive CORE settings & set appropriate values
	
	// API Key
	$httpBL_api_key = yourls_get_option( 'httpBL_api_key' );
	
	// Custom http:BL block page
	$httpBL_cstm_block_tgl = yourls_get_option( 'httpBL_cstm_block_tgl' );
	if ($httpBL_cstm_block_tgl == "true") {
		$url_chk = 'checked';
	} else {
		$url_chk = null;
	}
	$httpBL_cstm_block = yourls_get_option( 'httpBL_cstm_block' );
	
	// Preserve white list on deactivate?
	$httpBL_table_drop_wl = yourls_get_option( 'httpBL_table_drop_wl' );
	if ($httpBL_table_drop_wl !== "false") {
		$drop_chk_wl = 'checked';
	} else {
		$drop_chk_wl = null;
	}
	
	// Preserve logs on deactivate?
	$httpBL_table_drop_log = yourls_get_option( 'httpBL_table_drop_log' );
	if ($httpBL_table_drop_log !== "false") {		// default = true
		$drop_chk_log = 'checked';
	} else {
		$drop_chk_log = null;
	}
	
	// Log Blocked visitors?		
	$httpBL_log_blocked = yourls_get_option( 'httpBL_log_blocked' );
	if ($httpBL_log_blocked == "true") {
		$lb_chk = 'checked';
	} else {
		$lb_chk = null;
	}
	
	// Log Unblocked visitors?		
	$httpBL_log_unblocked = yourls_get_option( 'httpBL_log_unblocked' );
	if ($httpBL_log_unblocked == "true") {
		$lub_chk = 'checked';
	} else {
		$lub_chk = null;
	}
	
	// Show log tab?
	if ( ($httpBL_log_blocked == "true") || ($httpBL_log_unblocked == "true") ) {
		$log_vis = 'inline';
	} else { 
		$log_vis = 'none';
	}
	
	// CHECK if the DATABASE FLUSH LOGS form was submitted
	httpBL_flush_logs();
	
	// CHECK if the DATABASE FLUSH WL form was submitted
	httpBL_flush_wl();

	// Create nonce
	$nonce = yourls_create_nonce( 'httpBL' );

	// Main interface html
	$vars = array();
		$vars['httpBL_api_key'] = $httpBL_api_key;
		$vars['httpBL_cstm_block_tgl'] = $httpBL_cstm_block_tgl;
		$vars['httpBL_cstm_block'] = $httpBL_cstm_block;
		$vars['httpBL_table_drop_wl'] = $httpBL_table_drop_wl;
		$vars['httpBL_table_drop_log'] = $httpBL_table_drop_log;
		$vars['httpBL_log_blocked'] = $httpBL_log_blocked;
		$vars['httpBL_log_unblocked'] = $httpBL_log_unblocked;
		$vars['url_chk'] = $url_chk;
		$vars['drop_chk_log'] = $drop_chk_log;
		$vars['drop_chk_wl'] = $drop_chk_wl;
		$vars['lb_chk'] = $lb_chk;
		$vars['lub_chk'] = $lub_chk;
		$vars['log_vis'] = $log_vis;
		
		$vars['nonce'] = $nonce;

	$opt_view = file_get_contents( dirname( __FILE__ ) . '/inc/opt.php', NULL, NULL, 212);
	// Replace all %stuff% in opt with variable $stuff
	$opt_view = preg_replace_callback( '/%([^%]+)?%/', function( $match ) use( $vars ) { return $vars[ $match[1] ]; }, $opt_view );

	echo $opt_view;
	
	// Whitelist page - check inc/wl.php
	httpBL_wl_mgr($nonce);
	
	// log view page
	httpBL_log_view($log_vis,$nonce);
	
	// Close the initial html divs opened in opt.php
			echo "</div>\n";
		echo "</div>\n";
	echo "</div>\n";
}
// Admin page - log view
function httpBL_log_view($log_vis,$nonce) {
	// should we bother with this data, has the "nuke" option been set?"
	$log_blocked = yourls_get_option( 'httpBL_log_blocked' );
	$log_unblocked = yourls_get_option( 'httpBL_log_unblocked' );
	if ( ($log_blocked == "true") || ($log_unblocked == "true") ) {
		// Log are checked ~ this picks up where opt.0.php leaves off.
		global $ydb;
		echo <<<HTML
		<div style="display:$log_vis;" id="stat_tab_logs" class="tab">

			<h3>Empty Log Table</h3>

			<form method="post">
				<div class="checkbox">
				  <label>
					<input name="httpBL_flush_logs" type="hidden" value="no" />
					<input name="httpBL_flush_logs" type="checkbox" value="yes"> Check here and FLUSH! to empty the logs.
				  </label>
				</div>
				<input type="hidden" name="nonce" value="$nonce" />
				<p><input type="submit" value="FLUSH!" /></p>
			</form>
			<h3>http:BL Log Table</h3>
			
			<p>These values are from Project Honeypot. More information on that can be found <a href="https://www.projecthoneypot.org/httpBL_api.php" target="_blank">here</a>.</p>
			
				<table id="main_table" class="tblSorter" border="1" cellpadding="5" style="border-collapse: collapse">
					<thead>
						<tr>
							<th>IP Address</th>
							<th>Action</th>
							<th>Type</th>
							<th>Score</th>
							<th>Recency</th>
							<th>Time of Incident</th>
						</tr>
					</thead>
					<tbody>
HTML;
		// populate table rows with flag data if there is any
		$logs = $ydb->get_results("SELECT * FROM `httpBL_log` ORDER BY timestamp DESC");
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
	echo "</div>\n";
}
?>
