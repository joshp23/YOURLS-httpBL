<?php
/**
Plugin Name: HTTP:BL
Plugin URI: https://github.com/joshp23/YOURLS-httpBL
Description: An implementation of Project Honeypot's http:BL for YOURLS
Version: 2.0.1
Author: Josh Panter
Author URI: https://unfettered.net
**/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
httpBL_human_check(); 
/*
 *
 *	Admin Page
 *
 *
*/
// Register admin forms
yourls_add_action( 'plugins_loaded', 'httpBL_add_pages' );
function httpBL_add_pages() {
        yourls_register_plugin_page( 'httpBL', 'HTTP:BL', 'httpBL_do_page' );
}
// Admin page
function httpBL_do_page() {

	// CHECK form submition
	httpBL_update_opts();
	httpBL_flush_logs();
	httpBL_flush_wl();
	
	// Retreive settings & defaults
	$opt = httpBL_getops();

	// Set some values for display
	$url_chk 		= ( $opt[1] == "true" ? 'checked' : null );	// Use custom http:BL block page?
	$drop_chk_wl 	= ( $opt[3] == "true" ? 'checked' : null );	// Drop white list on deactivate?
	$drop_chk_log 	= ( $opt[4] == "true" ? 'checked' : null );	// Drop logs on deactivate?
	$lb_chk 		= ( $opt[5] == "true" ? 'checked' : null );	// Log Blocked visitors?
	$lub_chk 		= ( $opt[6] == "true" ? 'checked' : null );	// Log Unblocked visitors?
	$log_vis 		= ( $opt[5] == "true" || $opt[6] == "true" ? 'inline' : 'none' );	// Show log tab?

	// Create nonce
	$nonce 	= yourls_create_nonce( 'httpBL' );

	echo <<<HTML
	<link rel="stylesheet" href="/css/infos.css?v=1.7.2" type="text/css" media="screen" />
	<script src="/js/infos.js?v=1.7.2" type="text/javascript"></script>

	<div id="wrap">
		<div id="tabs">

			<div class="wrap_unfloat">
				<ul id="headers" class="toggle_display stat_tab">
					<li class="selected"><a href="#stat_tab_behavior"><h2>http:BL Config</h2></a></li>
					<li><a href="#stat_tab_httpBL_wl"><h2>White List</h2></a></li>
					<li style="display:$log_vis;"><a href="#stat_tab_logs"><h2>Logs</h2></a></li>
				</ul>
			</div>

			<div id="stat_tab_behavior" class="tab">

				<form method="post">
					<h3>Project Honeypot API Key</h3>

					<p>In order to use http:BL you need to have a Project Honeypot API key. For information on how to become a member of the project and get yourself a free key, please click <a href="https://www.projecthoneypot.org/" target="_blank">here</a>. Otherwise, please enter your key below.</p>
					<p><label for="httpBL_api_key">Your Key  </label> <input type="text" size=20 id="httpBL_api_key" name="httpBL_api_key" value="$opt[0]" /></p>

					<h3>Block Page</h3>
					<div class="checkbox">
					  <label>
						<input name="httpBL_cstm_block_tgl" type="hidden" value="false" />
						<input name="httpBL_cstm_block_tgl" type="checkbox" value="true" $url_chk >Use custom block page URL?
					  </label>
					</div>
					<div>
						<p>Setting the above option without setting this will fall back to default behavior.</p>
						<p><label for="httpBL_cstm_block">Enter custome block page URL here</label> <input type="text" size=40 id="httpBL_cstm_block" name="httpBL_cstm_block" value="$opt[2]" /></p>
					</div>
					
					<h3>Table Management</h3>
					
					<p>Would you like to keep logs?</p>
					<div class="checkbox">
					  <label>
						<input name="httpBL_log_blocked" type="hidden" value="false" />
						<input name="httpBL_log_blocked" type="checkbox" value="true" $lb_chk > Log visitor block events?
					  </label>
					</div>
					<div class="checkbox">
					  <label>
						<input name="httpBL_log_unblocked" type="hidden" value="false" />
						<input name="httpBL_log_unblocked" type="checkbox" value="true" $lub_chk > Log visitor unblock events (passed cookie)?
					  </label>
					</div>
					
					<p>This plugin automatically drops its databse tables when disabled. You can override this here.</p>
					<div class="checkbox">
					  <label>
						<input name="httpBL_table_drop_log" type="hidden" value="false" />
						<input name="httpBL_table_drop_log" type="checkbox" value="true" $drop_chk_log > Drop the logs when disabled?
					  </label>
				        </div>
				        <div class="checkbox">
					  <label>
						<input name="httpBL_table_drop_wl" type="hidden" value="false" />
						<input name="httpBL_table_drop_wl" type="checkbox" value="true" $drop_chk_wl > Drop the white list when disabled?
					  </label>
					</div>
					
					<input type="hidden" name="nonce" value="$nonce" />
					<p><input type="submit" value="Submit" /></p>
				</form>
			</div>
HTML;
	// Whitelist page
	httpBL_wl_mgr($nonce);
	// log view page
	httpBL_log_view($log_vis,$nonce);
	// Close the html
	echo <<<HTML
		</div>
	</div>
HTML;
}
// Admin whitelist page 0 - Handle WL form submisions and list logic 
function httpBL_wl_mgr() {
	if( isset( $_GET['action'] ) && $_GET['action'] == 'wl_remove' ) {
		httpBL_wl_remove();		// 0.3
	} else if( isset( $_POST['action'] ) && $_POST['action'] == 'wl_add' ) {
    	httpBL_wl_add();		// 0.2
	} else {
        httpBL_wl_list();		// 0.1
	}
}
// Admiin whitelist page 0.1 - printing the list
function httpBL_wl_list() {

	global $ydb;
	$cip = yourls_get_ip();
	$q = httpBL_wl_chk($cip);
	if ($q == true) { 
		$a = 'is';
	} else {
		$a = 'is not';
	}
	echo <<<HTML
			<div  id="stat_tab_httpBL_wl" class="tab">
				<h3>http:BL White List</h3>
				<p>Any IP listed here will skip http:BL checks. Your currnet IP: <strong>$cip</strong> $a in the white list.</p>
				<form method="post">
					<table id="main_table" class="tblSorter" border="1" cellpadding="5" style="border-collapse: collapse">
						<thead>
							<tr>
								<th>IP Address</th>
								<th>Notes</th>
								<th>Added</th>
								<th>&nbsp;</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td><input type="text" name="ip" placeholder="Leave empty for current ip."></td>
								<td><input type="text" name="notes" size=30></td>
								<td><input type="text" name="date" size=12 disabled></td>
								<td colspan=3 align=right>
									<input type=submit name="submit" value="Add">
									<input type="hidden" name="action" value="wl_add">
								</td>
							</tr>
HTML;
		
	// populate table rows with flag data if there is any
	$table = 'httpBL_wl';
	$httpBL_white_listed = $ydb->get_results("SELECT * FROM `$table` ORDER BY timestamp DESC");
	$found_rows = false;
	if($httpBL_white_listed) {
		$found_rows = true;
		foreach( $httpBL_white_listed as $wl_item ) {
			$ip = $wl_item->ip;
			$timestamp = strtotime($wl_item->timestamp);
			$notes = $wl_item->notes;
			$date = date( 'M d, Y H:i', $timestamp);
			$wl_remove = ''. $_SERVER['PHP_SELF'] .'?page=httpBL&action=wl_remove&ip='. $ip .'';
			// print if there is any data
			echo <<<HTML
							<tr>
								<td>$ip</td>
								<td>$notes</td>
								<td>$date</td>
								<td><a href="$wl_remove">Remove <img src="/images/delete.png" title="Remove" border=0></a></td>
							</tr>
HTML;
		}
	}
	echo <<<HTML
						</tbody>
					</table>
				</form>
		
				<h3>Revoke all</h3>

				<form method="post">
					<div class="checkbox">
					  <label>
						<input name="httpBL_flush_wl" type="hidden" value="no" />
						<input name="httpBL_flush_wl" type="checkbox" value="yes"> Check here and click 'REVOKE ALL!' to drop all IP's from the list.
					  </label>
					</div>
					<p><input type="submit" value="REVOKE ALL!" /></p>
				</form>
			</div>
HTML;
}
// Admin whitelist page 0.2 - adding to list
function httpBL_wl_add() {
	global $ydb;
	
	if (!empty($_POST) && isset($_POST['ip']) && isset($_POST['notes'])){
		// Try to determine IP automatically
		if (!$_POST['ip']) {
			$ip = yourls_get_ip();
			// note the event
			if (!$_POST['notes'] == '') {
				$notes = 'IP detected autoamtically';
			} else {
				$notes = $_POST['notes'];
			}
		} else {
			$ip = $_POST['ip'];
		}
		
		$notes = $_POST['notes'];
		$redundant_chk = httpBL_wl_chk($ip);
		
		if ( $redundant_chk == true ) {
			echo '<h3 style="color:green">IP was already in whitelist.</h3>';
		} else {
			$insert = $ydb->query("REPLACE INTO `httpBL_wl` (ip, notes) VALUES ('$ip', '$notes')");
			echo '<h3 style="color:green">IP added to the whitelist. Have a nice day.</h3>';
		}
	}

	httpBL_wl_list();
}
// / Admiin whitelist page 0.3 - removing from list
function httpBL_wl_remove() {
	global $ydb;

	if( isset($_GET['ip']) ) {
		$ip = $_GET['ip'];
        	$delete = $ydb->query("DELETE FROM `httpBL_wl` WHERE ip='$ip'");
        	echo '<h3 style="color:green">IP removed from the whitelist. Have a nice day.</h3>';
	}
	httpBL_wl_list();
}
// Admin page - log view
function httpBL_log_view($log_vis,$nonce) {
	$opt = httpBL_getops ();
	// should we bother with this data?"
	if ( ($opt[5] == "true") || ($opt[6] == "true") ) {
		// Log are checked
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
/*
 *
 *	Form Submissions
 *
 *
*/
// CORE options form
function httpBL_update_opts() {
	if(isset( $_POST['httpBL_api_key'])) {
		// Check nonce
		yourls_verify_nonce( 'httpBL' );
		// Set options
		yourls_update_option( 'httpBL_api_key', $_POST['httpBL_api_key'] );
		if( isset($_POST['httpBL_cstm_block_tgl'])) yourls_update_option( 'httpBL_cstm_block_tgl', $_POST['httpBL_cstm_block_tgl'] );
		if( isset($_POST['httpBL_cstm_block'])) yourls_update_option( 'httpBL_cstm_block', $_POST['httpBL_cstm_block'] );
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
			$init_log_1 = yourls_get_option('httpBL_init_log');

			if ($init_log_1 !== false) {
				$ydb->query("TRUNCATE TABLE `httpBL_log`");
				yourls_update_option('httpBL_init_log', time());
				$init_log_2 = yourls_get_option('httpBL_init_log');
				if ($init_log_2 == false || $init_log_1 == $init_log_2) {
					die("Unable to properly reset the log database. Contact your sys admin");
				}
			}
			echo '<h3 style="color:green">Database reset, all logs dropped. Have a nice day!</h3>';
		}
	}
}
// Flush Whitelist
function httpBL_flush_wl() {
	if( isset( $_POST['httpBL_flush_wl'] ) ) {
		if( $_POST['httpBL_flush_wl'] == 'yes' ) {
		// Check nonce
			$init_wl_1 = yourls_get_option('httpBL_init_wl');
			if ($init_wl_1 !== false) {
				$ydb->query("TRUNCATE TABLE `httpBL_wl`");
				yourls_update_option('httpBL_init_wl', time());
				$init_wl_2 = yourls_get_option('httpBL_init_wl');
				if ($init_wl_2 == false || $init_wl_1 == $init_wl_2) {
					die("Unable to properly reset the whitelist database. Contact your sys admin");
				}
			}
			echo '<h3 style="color:green">Database reset, all priviledges revoked. Have a nice day!</h3>';
		}
	}
}
/*
 *
 *	Core Function
 *
 *
*/
// Get options and set defaults
function httpBL_getops() {

	// Get values from DB
	$key = yourls_get_option( 'httpBL_api_key' );
	$cbt = yourls_get_option( 'httpBL_cstm_block_tgl' );
	$cb  = yourls_get_option( 'httpBL_cstm_block' );
	$tdw = yourls_get_option( 'httpBL_table_drop_wl' );
	$tdl = yourls_get_option( 'httpBL_table_drop_log' );
	$lx  = yourls_get_option( 'httpBL_log_blocked' );
	$l0  = yourls_get_option( 'httpBL_log_unblocked' );

	// Set defaults if necessary
	if( $cbt == null ) $cbt = 'false';
	if( $tdw == null ) $tdw = 'true';
	if( $tdl == null ) $tdw = 'true';
	if( $lx  == null ) $lx  = 'false';
	if( $l0  == null ) $l0  = 'false';

	return array(
		$key,	// $opt[0]
		$cbt,	// $opt[1]
		$cb,	// $opt[2]
		$tdw,	// $opt[3]
		$tdl,	// $opt[4]
		$lx,	// $opt[5]
		$l0		// $opt[6]
	);
}
// Initial cookie check
function httpBL_human_check() {

	$opt = httpBL_getops();
	$ip = yourls_get_ip();
	$wl = httpBL_wl_chk($ip);

	if($wl == false) {
		if(isset($_COOKIE['notabot'])) {
			if ($opt[6] == "true") httpBL_logme(false,	$ip);
		} else {
			httpBL_check($opt);
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
function httpBL_check($opt) {

	$ip = yourls_get_ip();

	// build the lookup DNS query
	// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.httpBL.org'
	$lookup = $opt[0] . '.' . implode('.', array_reverse(explode ('.', $ip ))) . '.dnsbl.httpBL.org';
	
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
			if ($opt[5] == "true") httpBL_logme($block,$ip,$typemeaning,$threat,$activity);
			httpBL_blockme($ip,$typemeaning,$threat,$opt);
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
function httpBL_blockme($ip,$typemeaning,$threat,$opt) {
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
		if (($opt[1] == "true") && ($opt[2] !== '')) {
			// Send to custom block page and die
			yourls_redirect( $opt[2], 302 );
			die ();
		}
		// Or go to default
		httpBL_display_blockpage($ip,$typemeaning,$threat);
	}
}
// Secondary block function: display template block page
function httpBL_display_blockpage($ip,$typemeaning,$threat) {

	$img   = yourls_plugin_url( dirname( __FILE__ ).'/assets/no-entry.png' );
	$css   = yourls_plugin_url( dirname( __FILE__ ).'/assets/bootstrap.min.css' );

	$vars = array();
		$vars['ip'] = $ip;
		$vars['typemeaning'] = $typemeaning;
		$vars['threat'] = $threat;
		$vars['img'] = $img;
		$vars['css'] = $css;

	$blockpage = file_get_contents( dirname( __FILE__ ) . '/assets/blockpage.php' );
	// Replace all %stuff% in intercept.php with variable $stuff
	$blockpage = preg_replace_callback( '/%([^%]+)?%/', function( $match ) use( $vars ) { return $vars[ $match[1] ]; }, $blockpage );

	echo $blockpage;

	die();
}
/*
 *
 *	Database Functions
 *
 *
*/
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
		$table_httpBL_log .= "page varchar(255) NOT NULL, ";
		$table_httpBL_log .= "ua varchar(255) NOT NULL, ";
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
		$table_httpBL_wl .= "notes varchar(255) NOT NULL, ";
		$table_httpBL_wl .= "PRIMARY KEY (timestamp) ";
		$table_httpBL_wl .= ") ENGINE=MyISAM DEFAULT CHARSET=latin1;";
		$tables = $ydb->query($table_httpBL_wl);

		yourls_update_option('httpBL_init_wl', time());
		$init_wl = yourls_get_option('httpBL_init_wl');
		if ($init_wl === false) {
			die("Unable to properly enable http:BL due an apparent problem with the whitelist database.");
		}
	}
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
}
?>
