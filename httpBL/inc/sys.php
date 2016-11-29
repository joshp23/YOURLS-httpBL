<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Core sys functions
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

// Initial cookie check
function httpBL_human_check() {

	$ip = yourls_get_ip();
	$httpBL_wl = httpBL_wl_chk($ip);
	if($httpBL_wl == false) {
		if(isset($_COOKIE['notabot'])) {
			$log_unblocked = yourls_get_option( 'httpBL_log_unblocked' );
			if ($log_unblocked == "true") httpBL_logme(false,	$ip);
		} else {
			httpBL_check();
		}
	}
}

// Is whitelisted?
function httpBL_wl_chk($ip) {
	global $ydb;

	$result = false;
	
	$w_listed = $ydb->get_row("SELECT * FROM `httpBL_wl` WHERE `ip` = '$ip'");
	
	if( $w_listed ) $result = true;

	return $result;
}

// Check visitor IP
function httpBL_check() {	
	$apikey = yourls_get_option( 'httpBL_api_key' );
	$ip = yourls_get_ip();
	// build the lookup DNS query
	// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.httpbl.org'
	$lookup = $apikey . '.' . implode('.', array_reverse(explode ('.', $ip ))) . '.dnsbl.httpbl.org';
	
	// check query response
	$result = explode( '.', gethostbyname($lookup));
	
	if ($result[0] == 127) {
		// query successful !
		$activity = $result[1];
		$threat = $result[2];
		$type = $result[3];
		
		$typemeaning = '';
		if ($type == 0) $typemeaning = 'Search Engine';
		if ($type == 1) $typemeaning = 'Suspicious';
		if ($type == 2) $typemeaning = 'Harvester';
		if ($type == 3) $typemeaning = 'Suspicious & Harvester';
		if ($type == 4) $typemeaning = 'Comment Spammer';
		if ($type == 5) $typemeaning = 'Suspicious & Comment Spammer';
		if ($type == 6) $typemeaning = 'Harvester & Comment Spammer';
		if ($type == 7) $typemeaning = 'Suspicious, Harvester, & Comment Spammer';
		
		
		// Now determine some blocking policy
		if (
		($type >= 4 && $threat > 0) // Comment spammer with any threat level
			||
		($type < 4 && $threat > 20) // Other types, with threat level greater than 20
		) {
			$block = true;
		}
		
		if ($block) {
			$log_blocked = yourls_get_option( 'httpBL_log_blocked' );
			if ($log_blocked == "true") httpBL_logme($block,$ip,$typemeaning,$threat,$activity);
			httpBL_blockme($ip,$typemeaning,$threat);
		}
	
	}
}

// Logging block and unblock events
function httpBL_logme($block = false, $ip='', $typemeaning='',$threat='',$activity='') {
	global $ydb;
		
	// Some stuff you could log for further analysis
	$page = $_SERVER['REQUEST_URI'];
	$ua = yourls_get_user_agent();
		
	if ($block) {
		$action = 'BLOCKED';
	} else {
		$action = 'UNBLOCKED';
	}

	$insert = $ydb->query("INSERT INTO `httpBL_log` (action, ip, type, threat, activity, page, ua) VALUES ('$action', '$ip', '$typemeaning', '$threat', '$activity', '$page', '$ua')");
}

// Primary blocking function
function httpBL_blockme($ip,$typemeaning,$threat) {
	// API mode 
	if ( yourls_is_API() ) {
		$format = ( isset($_REQUEST['format']) ? $_REQUEST['format'] : 'xml' );
		$callback = ( isset($_REQUEST['callback']) ? $_REQUEST['callback'] : '' );
		yourls_api_output( $format, array(
			'simple' => 'Error: Your IP has been blacklisted',
			'message' => 'Error: Forbidden: http:bl',
			'errorCode' => 403,
			'callback' => $callback,
		) );
		die();
	// Regular Mode
	} else {
		// use custom block page?
		$httpBL_cstm_block_tgl = yourls_get_option( 'httpBL_cstm_block_tgl' );
		$httpBL_cstm_block = yourls_get_option( 'httpBL_cstm_block' );
		if (($httpBL_cstm_block_tgl == "true") && ($httpBL_cstm_block !== '')) {
			// Send to custom block page and die
			yourls_redirect( $httpBL_cstm_block, 302 );
			die ();
		}
		// Or go to default
		httpBL_display_blockpage($ip,$typemeaning,$threat);
	}
}
// Secondary block function: display template block page
function httpBL_display_blockpage($ip,$typemeaning,$threat) {

	$img   = yourls_plugin_url( dirname( __FILE__ ).'/../assets/no-entry.png' );
	$css   = yourls_plugin_url( dirname( __FILE__ ).'/../assets/bootstrap.min.css' );

	$vars = array();
		$vars['ip'] = $ip;
		$vars['typemeaning'] = $typemeaning;
		$vars['threat'] = $threat;
		$vars['img'] = $img;
		$vars['css'] = $css;

	$blockpage = file_get_contents( dirname( __FILE__ ) . '/../assets/blockpage.php' );
	// Replace all %stuff% in intercept.php with variable $stuff
	$blockpage = preg_replace_callback( '/%([^%]+)?%/', function( $match ) use( $vars ) { return $vars[ $match[1] ]; }, $blockpage );

	echo $blockpage;

	die();
}
// CORE options form
function httpBL_update_op_core() {
	if(isset( $_POST['httpBL_api_key'])) {
		// Check nonce
		yourls_verify_nonce( 'httpBL' );
		// Set options
		yourls_update_option( 'httpBL_api_key', $_POST['httpBL_api_key'] );
		if(isset($_POST['httpBL_cstm_block_tgl'])) yourls_update_option( 'httpBL_cstm_block_tgl', $_POST['httpBL_cstm_block_tgl'] );
		if(isset($_POST['httpBL_cstm_block'])) yourls_update_option( 'httpBL_cstm_block', $_POST['httpBL_cstm_block'] );
		if( isset( $_POST['httpBL_table_drop_log'])) yourls_update_option( 'httpBL_table_drop_log', $_POST['httpBL_table_drop_log'] );
		if( isset( $_POST['httpBL_table_drop_wl'])) yourls_update_option( 'httpBL_table_drop_wl', $_POST['httpBL_table_drop_wl'] );
		if( isset( $_POST['httpBL_log_blocked'])) yourls_update_option( 'httpBL_log_blocked', $_POST['httpBL_log_blocked'] );
		if( isset( $_POST['httpBL_log_unblocked'])) yourls_update_option( 'httpBL_log_unblocked', $_POST['httpBL_log_unblocked'] );
	}
}
// Flush logs
function httpBL_flush_logs() {
	if( isset( $_POST['httpBL_flush_logs'] ) ) {
		if( $_POST['httpBL_flush_logs'] == 'yes' ) {
		// Check nonce
		yourls_verify_nonce( 'httpBL' );
		httpBL_flush_logs_do();
		echo '<h3 style="color:green">Database reset, all logs dropped. Have a nice day!</h3>';
		}
	}
}
// Flush Whitelist
function httpBL_flush_wl() {
	if( isset( $_POST['httpBL_flush_wl'] ) ) {
		if( $_POST['httpBL_flush_wl'] == 'yes' ) {
		// Check nonce
		httpBL_flush_wl_do();
		echo '<h3 style="color:green">Database reset, all priviledges revoked. Have a nice day!</h3>';
		}
	}
}
?>
