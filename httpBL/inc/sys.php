<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Core sys functions
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

// Initial cookie check
function httpbl_human_check() {
	if(isset($_COOKIE['notabot'])) {
		$log_unblocked = yourls_get_option( 'httpbl_log_unblocked' );
		if ($log_unblocked == "true") {
			$ip = yourls_get_ip();
			httpbl_logme(false,	$ip);
		}
	} else {
		httpbl_check();
	}
}

// Check visitor IP
function httpbl_check() {	
	$apikey = yourls_get_option( 'httpbl_api_key' );
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
			$log_blocked = yourls_get_option( 'httpbl_log_blocked' );
			if ($log_blocked == "true") httpbl_logme($block,$ip,$typemeaning,$threat,$activity);
			httpbl_blockme($ip,$typemeaning,$threat);
		}
	
	}
}

// Logging block and unblock events
function httpbl_logme($block = false, $ip='', $typemeaning='',$threat='',$activity='') {
	global $ydb;
	
	$table = "httpbl";
	
	// Some stuff you could log for further analysis
	$page = $_SERVER['REQUEST_URI'];
	$ua = yourls_get_user_agent();
		
	if ($block) {
		$action = 'BLOCKED';
	} else {
		$action = 'UNBLOCKED';
	}

	$insert = $ydb->query("INSERT INTO `$table` (action, ip, type, threat, activity, page, ua) VALUES ('$action', '$ip', '$typemeaning', '$threat', '$activity', '$page', '$ua')");
}

// Primary blocking function
function httpbl_blockme($ip,$typemeaning,$threat) {
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
		$httpbl_cstm_block_tgl = yourls_get_option( 'httpbl_cstm_block_tgl' );
		$httpbl_cstm_block = yourls_get_option( 'httpbl_cstm_block' );
		if (($httpbl_cstm_block_tgl == "true") && ($httpbl_cstm_block !== '')) {
			// Send to custom block page and die
			yourls_redirect( $httpbl_cstm_block, 302 );
			die ();
		}
		// Or go to default
		httpbl_display_blockpage($ip,$typemeaning,$threat);
	}
}
// Secondary block function: display template block page
function httpbl_display_blockpage($ip,$typemeaning,$threat) {

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
function httpbl_update_op_core() {
	if(isset( $_POST['httpbl_api_key'])) {
		// Check nonce
		yourls_verify_nonce( 'httpbl' );
		// Set options
		yourls_update_option( 'httpbl_api_key', $_POST['httpbl_api_key'] );
		if(isset($_POST['httpbl_cstm_block_tgl'])) yourls_update_option( 'httpbl_cstm_block_tgl', $_POST['httpbl_cstm_block_tgl'] );
		if(isset($_POST['httpbl_cstm_block'])) yourls_update_option( 'httpbl_cstm_block', $_POST['httpbl_cstm_block'] );
		if( isset( $_POST['httpbl_table_drop'])) yourls_update_option( 'httpbl_table_drop', $_POST['httpbl_table_drop'] );
		if( isset( $_POST['httpbl_log_blocked'])) yourls_update_option( 'httpbl_log_blocked', $_POST['httpbl_log_blocked'] );
		if( isset( $_POST['httpbl_log_unblocked'])) yourls_update_option( 'httpbl_log_unblocked', $_POST['httpbl_log_unblocked'] );
	}
}
// Flush logs
function httpbl_flush_logs() {
	if( isset( $_POST['httpbl_flush_logs'] ) ) {
		if( $_POST['httpbl_flush_logs'] == 'yes' ) {
		// Check nonce
		yourls_verify_nonce( 'httpbl' );
		httpbl_db_flush();
		echo 'Database reset, all logs dropped. Have a nice day!';
		}
	}
}
?>
