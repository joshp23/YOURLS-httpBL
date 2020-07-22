<?php
/**
Plugin Name: HTTP:BL
Plugin URI: https://github.com/joshp23/YOURLS-httpBL
Description: An implementation of Project Honeypot's http:BL for YOURLS
Version: 2.4.0
Author: Josh Panter
Author URI: https://unfettered.net
**/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
if (yourls_get_option('httpBL_init_log') == true && !defined( 'HTTPBL_DB_UPDATE' ) ) httpBL_human_check();
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
// Maybe insert some JS and CSS files to head
yourls_add_action( 'html_head', 'httpBL_head' );
function httpBL_head($context) {
	if ( $context[0] == 'plugin_page_httpBL' ) {
		$home = YOURLS_SITE;
		echo "<link rel=\"stylesheet\" href=\"".$home."/css/infos.css?v=".YOURLS_VERSION."\" type=\"text/css\" media=\"screen\" />\n";
		echo "<script src=\"".$home."/js/infos.js?v=".YOURLS_VERSION."\" type=\"text/javascript\"></script>\n";
	}
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
	$bp = array("template" => "", "native" => "", "url" => "");
	switch ($opt[1]) {
		case 'native': 
			$bp['native'] = 'selected';
			break;
		case 'topright':
			$bo['url'] = 'url';
			break;
		default:
			$bp['template'] = 'template';
			break;
	}
	$drop_chk_wl 	= ( $opt[3] == "true" ? 'checked' : null );	// Drop white list on deactivate?
	$drop_chk_log 	= ( $opt[4] == "true" ? 'checked' : null );	// Drop logs on deactivate?
	$lb_chk 	= ( $opt[5] == "true" ? 'checked' : null );	// Log Blocked visitors?
	$lub_chk	= ( $opt[6] == "true" ? 'checked' : null );	// Log Unblocked visitors?
	$log_vis	= ( $opt[5] == "true" || $opt[6] == "true" ? 'inline' : 'none' );	// Show log tab?

	// Misc for cron example pre-formatting
	$sig	= yourls_auth_signature();
	$site   = YOURLS_SITE;
	$cronEG   =  rawurlencode('<html><body><pre>0 * * * * wget -O - -q -t 1 <strong>'.$site.'</strong>/yourls-api.php?signature=<strong>'.$sig.'</strong>&format=simple&action=httpBL-WL >/dev/null 2>&1</pre></body></html>');

	// Create nonce
	$nonce 	= yourls_create_nonce( 'httpBL' );

	echo <<<HTML

	<div id="wrap">
		<div id="tabs">

			<div class="wrap_unfloat">
				<ul id="headers" class="toggle_display stat_tab">
					<li class="selected"><a href="#stat_tab_behavior"><h2>http:BL Config</h2></a></li>
					<li><a href="#stat_tab_httpBL_wl"><h2>White List</h2></a></li>
					<li style="display:$log_vis;"><a href="#stat_tab_logs"><h2>Logs</h2></a></li>
					<li><a href="#stat_tab_httpBL_api"><h2>API</h2></a></li>
				</ul>
			</div>

			<div id="stat_tab_behavior" class="tab">

				<form method="post">
					<h3>Project Honeypot API Key</h3>

					<p>In order to use http:BL you need to have a Project Honeypot API key. For information on how to become a member of the project and get yourself a free key, please click <a href="https://www.projecthoneypot.org/" target="_blank">here</a>. Otherwise, please enter your key below.</p>
					<p><label for="httpBL_api_key">Your Key  </label> <input type="text" size=20 id="httpBL_api_key" name="httpBL_api_key" value="$opt[0]" /></p>

					<hr>
					<h3>Threshold levels</h3>
					<p>Threats are valued on a <a href="https://www.projecthoneypot.org/threat_info.php" target="_blank">scale</a> of 0 to 255, with 255 being the most elevated threat level. These settings define how different threats are handled based on this score: a setting of 0 will catch all threat levels, while a setting of 255 disables the check.</p>

					<p><Strong>Threat Level Tolelrance</strong>: Threat levels above this threshold will be blocked.</p>
					<p><strong>Grey Listing Tolelrance</strong>: Threat levels equal to or below this threshold will be presented a link to the site, bypassing checks for the rest of the session.</p>
	
					<table id="tolerance_table" class="tblSorter" border="1" cellpadding="5" style="border-collapse: collapse">
						<thead>
							<tr>
								<th>Threat Type</th>
								<th>Threat Level Tolerance</th>
								<th>Grey Listing Tolerance</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td>Search Engine: </td>
								<td><input type="number" id="httpBL_tlt_se" name="httpBL_tlt_se" min="0" max="255" value="{$opt[7]}"></td>
								<td><input type="number" id="httpBL_glt_se" name="httpBL_glt_se" min="0" max="255" value="{$opt[8]}"></td>
							</tr>
							<tr>
								<td>Suspicious: </td>
								<td><input type="number" id="httpBL_tlt_s" name="httpBL_tlt_s" min="0" max="255" value="{$opt[9]}"></td>
								<td><input type="number" id="httpBL_glt_s" name="httpBL_glt_s" min="0" max="255" value="{$opt[10]}"></td>
							</tr>
							<tr>
								<td>Harvester: </td>
								<td><input type="number" id="httpBL_tlt_h" name="httpBL_tlt_h" min="0" max="255" value="{$opt[11]}"></td>
								<td><input type="number" id="httpBL_glt_h" name="httpBL_glt_h" min="0" max="255" value="{$opt[12]}"></td>
							</tr>
							<tr>
								<td>Comment Spammer: </td>
								<td>All Comment Spammers are blocked</td>
								<td><input type="number" id="httpBL_glt_cs" name="httpBL_glt_cs" min="20" max="255" value="{$opt[13]}"></td>
							</tr>
						</tbody>
					</table>

					<hr>

					<h3>Block Page</h3>

				 	<select id="httpBL_block_page" name="httpBL_block_page">
					  <option value="template" {$bp['template']}>Use Template</option>
					  <option value="native" {$bp['native']}>Native style</option>
					  <option value="url" {$bp['url']}>Custom URL</option>
					</select> </br>

					<div id="httpBL_block_template" name="httpBL_block_template" style="display:none">
						<p>This will cause a file called <code>blockpage.php</code> in this plugin's assets folder to be executed.</p>
					</div>

					<div id="httpBL_block_native" name="httpBL_block_native" style="display:none">
						<p>This will draw a page using YOURLS native style.</p>
					</div>

					<div id="httpBL_block_url" name="httpBL_block_url" style="display:none">
						<p>Blocked users will be redirected to this URL with the following Request parameters:</p>
							<ul>
								<li><code>action</code> If the IP is to be grey or black listed</li>
								<li><code>ip</code> The offending IP address</li>
								<li><code>type</code> The threat type</li>
								<li><code>level</code> The threat level</li>
							</ul>
						<p>If left blank, httpBL will fall back to template.</p>
						<p>
							<label for="httpBL_cstm_block">URL: </label> 
							<input type="text" size=40 id="httpBL_cstm_block" name="httpBL_cstm_block" value="$opt[2]" />
						</p>
					</div>
					
					<script>
						document.getElementById('httpBL_tlt_se').addEventListener('change', function () {
							document.getElementById('httpBL_glt_se').min = this.value;
						});

						document.getElementById('httpBL_tlt_s').addEventListener('change', function () {
							document.getElementById('httpBL_glt_s').min = this.value;
						});

						document.getElementById('httpBL_tlt_h').addEventListener('change', function () {
							document.getElementById('httpBL_glt_h').min = this.value;
						});

						document.getElementById('httpBL_block_page').addEventListener('change', function () {
							var styleT = this.value == "template" ? 'block' : 'none';
							document.getElementById('httpBL_block_template').style.display = styleT;

							var styleN = this.value == "native" ? 'block' : 'none';
							document.getElementById('httpBL_block_native').style.display = styleN;

							var styleU = this.value == "url" ? 'block' : 'none';
							document.getElementById('httpBL_block_url').style.display = styleU;
						});
					</script>

					<hr>

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
			<div  id="stat_tab_httpBL_api" class="tab">
				<h3>Definitions</h3>
				<p>This plugin exposes a simple API for White List updating and maintanence. Using a cron job, an admin could keep an IP with a dynamically updating address current in the white-list.</p>
				<ul>
					<li><code>action=httpBL-WL</code> If sent alone, the transmitting IP will be added to the white-list if it is absent.</li>
					<li><code>note=STRING</code> Notes for when adding IP's to the white-list. Optional.</li>
					<li><code>deleteIP=VALID_IP</code> Self explanatory. Optional.</li>
				</ul>
				<p><strong>Note: </strong> API use is restricted to valid users only.</p>

				<h3>Cron example:</h3>
				<p>Use the following pre-formatted example to set up a daily cron job to check for IP updates:</p>
				 <iframe src="data:text/html;charset=utf-8,$cronEG" width="100%" height="51"/></iframe>
				<p>Look here for more info on <a href="https://help.ubuntu.com/community/CronHowto" target="_blank" >cron</a> and <a href="https://www.gnu.org/software/wget/manual/html_node/HTTP-Options.html" target="_blank">wget</a>.</p>
			</div>
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
	global $ydb;
	$table = YOURLS_DB_PREFIX . 'httpBL_wl';
	$sql = "SELECT * FROM `$table` ORDER BY timestamp DESC";
	$httpBL_white_listed = $ydb->fetchObjects($sql);
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
	
	if (!empty($_POST) && isset($_POST['ip']) && isset($_POST['notes'])){
		// Try to determine IP automatically
		if (!$_POST['ip']) {
			$ip = yourls_get_ip();
			// note the event
			if (!$_POST['notes']) {
				$notes = 'IP detected autoamtically';
			} else {
				$notes = $_POST['notes'];
			}
		} else {
			$ip = $_POST['ip'];
			if (!$_POST['notes']) {
				$notes = 'IP added manually';
			} else {
				$notes = $_POST['notes'];
			}
		}

		$redundant_chk = httpBL_wl_chk($ip);
		
		if ( $redundant_chk == true ) {
			echo '<h3 style="color:green">IP was already in whitelist.</h3>';
		} else {
			global $ydb;
			$table = YOURLS_DB_PREFIX . 'httpBL_wl';
			$binds = array('ip' => $ip, 'notes' => $notes);
			$sql = "REPLACE INTO `$table`  (ip, notes) VALUES (:ip, :notes)";
			$insert = $ydb->fetchAffected($sql, $binds);

			echo '<h3 style="color:green">IP added to the whitelist. Have a nice day.</h3>';
		}
	}

	httpBL_wl_list();
}
// / Admiin whitelist page 0.3 - removing from list
function httpBL_wl_remove() {

	if( isset($_GET['ip']) ) {
		$ip = $_GET['ip'];
			global $ydb;
			$table = YOURLS_DB_PREFIX . 'httpBL_wl';
			$binds = array('ip' => $ip, 'notes' => $notes);
			$sql = "DELETE FROM `$table`  WHERE ip=:ip";
			$delete = $ydb->fetchAffected($sql, $binds);

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
			
				<p>These values are from Project Honeypot. More information on the api can be found <a href="https://www.projecthoneypot.org/httpbl_api.php" target="_blank">here</a>.</p>
				<p>Information regarding the http:BL threat levels can be found <a href="https://www.projecthoneypot.org/threat_info.php" target="_blank">here</a>.</p>
			
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
		global $ydb;
		$table = YOURLS_DB_PREFIX . 'httpBL_log';
		$sql = "SELECT * FROM `$table` ORDER BY timestamp DESC";
		$logs = $ydb->fetchObjects($sql);
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
		if( isset($_POST['httpBL_block_page'])) yourls_update_option( 'httpBL_block_page', $_POST['httpBL_block_page'] );
		if( isset($_POST['httpBL_cstm_block'])) yourls_update_option( 'httpBL_cstm_block', $_POST['httpBL_cstm_block'] );
		if( isset( $_POST['httpBL_table_drop_log'])) yourls_update_option( 'httpBL_table_drop_log', $_POST['httpBL_table_drop_log'] );
		if( isset( $_POST['httpBL_table_drop_wl'])) yourls_update_option( 'httpBL_table_drop_wl', $_POST['httpBL_table_drop_wl'] );
		if( isset( $_POST['httpBL_log_blocked'])) yourls_update_option( 'httpBL_log_blocked', $_POST['httpBL_log_blocked'] );
		if( isset( $_POST['httpBL_log_unblocked'])) yourls_update_option( 'httpBL_log_unblocked', $_POST['httpBL_log_unblocked'] );
		if( isset( $_POST['httpBL_tlt_se'])) yourls_update_option( 'httpBL_tlt_se', $_POST['httpBL_tlt_se'] );
		if( isset( $_POST['httpBL_glt_se'])) yourls_update_option( 'httpBL_glt_se', $_POST['httpBL_glt_se'] );
		if( isset( $_POST['httpBL_tlt_s'])) yourls_update_option( 'httpBL_tlt_s', $_POST['httpBL_tlt_s'] );
		if( isset( $_POST['httpBL_glt_s'])) yourls_update_option( 'httpBL_glt_s', $_POST['httpBL_glt_s'] );
		if( isset( $_POST['httpBL_tlt_h'])) yourls_update_option( 'httpBL_tlt_h', $_POST['httpBL_tlt_h'] );
		if( isset( $_POST['httpBL_glt_h'])) yourls_update_option( 'httpBL_glt_h', $_POST['httpBL_glt_h'] );
		if( isset( $_POST['httpBL_glt_cs'])) yourls_update_option( 'httpBL_glt_cs', $_POST['httpBL_glt_cs'] );
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

				global $ydb;
				$table = 'httpBL_log';
				if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
					$sql = "TRUNCATE TABLE `$table`";
					$ydb->fetchAffected($sql);
				} else {
					$ydb->query("TRUNCATE TABLE `$table`");
				}

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

				global $ydb;
				$table = YOURLS_DB_PREFIX . 'httpBL_wl';
				$sql = "TRUNCATE TABLE `$table`";
				$ydb->fetchAffected($sql);

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
	$bp  = yourls_get_option( 'httpBL_block_page' );
	$cb  = yourls_get_option( 'httpBL_cstm_block' );
	$tdw = yourls_get_option( 'httpBL_table_drop_wl' );
	$tdl = yourls_get_option( 'httpBL_table_drop_log' );
	$lx  = yourls_get_option( 'httpBL_log_blocked' );
	$l0  = yourls_get_option( 'httpBL_log_unblocked' );
	$tse = yourls_get_option( 'httpBL_tlt_se' );
	$gse = yourls_get_option( 'httpBL_glt_se' );
	$ts  = yourls_get_option( 'httpBL_tlt_s' );
	$gs  = yourls_get_option( 'httpBL_glt_s' );
	$th  = yourls_get_option( 'httpBL_tlt_h' );
	$gh  = yourls_get_option( 'httpBL_glt_h' );
	$gcs = yourls_get_option( 'httpBL_glt_cs' );

	// Set defaults if necessary
	if( $bp == null )  $bp  = 'template';
	if( $tdw == null ) $tdw = 'true';
	if( $tdl == null ) $tdw = 'true';
	if( $lx  == null ) $lx  = 'false';
	if( $l0  == null ) $l0  = 'false';
	if( $tse == null ) $tse = 0;
	if( $gse == null ) $gse = 20;
	if( $ts  == null ) $ts  = 0;
	if( $gs  == null ) $gs  = 20;
	if( $th  == null ) $th  = 0;
	if( $gh  == null ) $gh  = 20;
	if( $gcs == null ) $gcs = 20;

	return array(
		$key,	// $opt[0]
		$bp,	// $opt[1]
		$cb,	// $opt[2]
		$tdw,	// $opt[3]
		$tdl,	// $opt[4]
		$lx,	// $opt[5]
		$l0,	// $opt[6]
		$tse,	// $opt[7]
		$gse,	// $opt[8]
		$ts,	// $opt[9]
		$gs,	// $opt[10]
		$th,	// $opt[11]
		$gh,	// $opt[12]
		$gcs	// $opt[13]
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
			httpBL_check($opt, $ip);
		}
	}
}
// Is whitelisted?
function httpBL_wl_chk($ip) {
	global $ydb;

	$result = false;

	$table = YOURLS_DB_PREFIX . 'httpBL_wl';
	$binds = array('ip' => $ip);
	$sql = "SELECT * FROM `$table`  WHERE `ip` = :ip";
	$w_listed = $ydb->fetchObject($sql, $binds);

	if( $w_listed ) $result = true;

	return $result;
}
// Check visitor IP
function httpBL_check($opt, $ip) {

	// build the lookup DNS query
	// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.httpBL.org'
	$querry = $opt[0] . '.' . implode('.', array_reverse(explode ('.', $ip ))) . '.dnsbl.httpbl.org';
	$lookup = gethostbyname($querry);
	// check query response
	$result = explode( '.', $lookup);
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
		switch( $type ) {
			// Search Engine with the configured value
			case 0:
				if ( $threat > $opt[7] ) $block = true;
				if ( $threat <= $opt[8] ) $greyList = true;
				break;
			// Suspicious activity with the configured value
			case 1:
				if ( $threat > $opt[9] ) $block = true;
				if ( $threat <= $opt[10] ) $greyList = true;
				break;
			// Harvester with the configured value
			case 2:
				if ( $threat > $opt[11] ) $block = true;
				if ( $threat <= $opt[12] ) $greyList = true;
				break;
			// Suspicious & Harvester with the configured values
			case 3:
				$thresholdT = min( $opt[9], $opt[11] ); // get the lowest threshold
				if ( $threat > $thresholdT ) $block = true;
				$thresholdG = min( $opt[10], $opt[12] ); // get the lowest threshold
				if ( $threat <= $thresholdG ) $greyList = true;
				break;
			// Comment spammer with any threat level, appropriate greylist
			case 4:
			case 5:
			case 6:
			case 7:
				if ( $threat > 0 ) $block = true;
				if ( $threat <= $opt[13] ) $greyList = true;
				break;
			default:
				$block = true;
				$greyList = true;
				break;
		}

		if ($block) {
			if ($opt[5] == "true") httpBL_logme($block,$ip,$typemeaning,$threat,$activity);
			httpBL_blockme($ip,$typemeaning,$threat,$greyList,$opt);
		}
	
	}
}
// Logging block and unblock events
function httpBL_logme($block = false, $ip='', $typemeaning='',$threat='',$activity='') {
		
	// Some stuff you could log for further analysis
	$page = $_SERVER['REQUEST_URI'];
	$ua = yourls_get_user_agent();
		
	if ($block) {
		$action = 'BLOCKED';
	} else {
		$action = 'UNBLOCKED';
	}

	global $ydb;
	$table = YOURLS_DB_PREFIX . 'httpBL_log';
	$binds = array('action' => $action, 
			'ip' => $ip, 
			'type' => $typemeaning, 
			'threat' => $threat, 
			'activity' => $activity, 
			'page' => $page, 
			'ua' => $ua
			);
	$sql = "INSERT INTO `$table`  (action, ip, type, threat, activity, page, ua) VALUES (:action, :ip, :type, :threat, :activity, :page, :ua)";
	$insert = $ydb->fetchAffected($sql, $binds);
}
// Primary blocking function
function httpBL_blockme($ip,$typemeaning,$threat,$greyList,$opt) {
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
		// Where do we send the offending ip?
		switch ($opt[1]) {
			case 'native': 
				httpBL_display_blockpage_native($ip,$typemeaning,$threat,$greyList);
				break;
			case 'url':
				if ($opt[2] !== '') {
					// Send to custom block page and die
					$action = $greylist ? 'greylist' : 'blacklist';
					$url = $opt[2].'?action='.$action.'&ip='.$ip.'&type='.$typemeaning.'&level='.$threat;
					yourls_redirect( $url, 302 );
					die ();
					break; // likely overkill, however: berevity
				}
			default:
				httpBL_display_blockpage_template($ip,$typemeaning,$threat,$greyList);
				break;
		}
	}
}
// Secondary block function: display template block page
function httpBL_display_blockpage_template($ip,$typemeaning,$threat,$greyList) {

	$img = yourls_plugin_url( dirname( __FILE__ ).'/assets/no-entry.png' );
	$css = yourls_plugin_url( dirname( __FILE__ ).'/assets/bootstrap.min.css' );
	if($greyList)
		$greyList = '<p>If you <strong>ARE NOT</strong> a bot of any kind, simply <a href="javascript:letmein()">click here</a> to gain access.</p>';

	$vars = array();
		$vars['ip'] 			= $ip;
		$vars['typemeaning'] 	= $typemeaning;
		$vars['threat'] 		= $threat;
		$vars['img'] 			= $img;
		$vars['css'] 			= $css;
		$vars['greyList'] 		= $greyList;

	$blockpage = file_get_contents( dirname( __FILE__ ) . '/assets/blockpage.php' );
	// Replace all %stuff% in intercept.php with variable $stuff
	$blockpage = preg_replace_callback( '/%([^%]+)?%/', function( $match ) use( $vars ) { return $vars[ $match[1] ]; }, $blockpage );

	echo $blockpage;

	die();
}
// Secondary block function: display template block page
function httpBL_display_blockpage_native($ip,$typemeaning,$threat,$greyList) {

	$img   = yourls_plugin_url( dirname( __FILE__ ).'/assets/no-entry.png' );
	if($greyList)
		$greyList = '<p>If you <strong>ARE NOT</strong> a bot of any kind, simply <a href="javascript:letmein()">click here</a> to gain access.</p>';
	$footer = yourls_s( 'Powered by %s', '<a href="http://yourls.org/" title="YOURLS">YOURLS</a> v ' . YOURLS_VERSION );
	$debug = null;
	if( defined( 'YOURLS_DEBUG' ) && YOURLS_DEBUG == true ) 
		$debug = '<div style="text-align:left"><pre>'.join( "\n", yourls_get_debug_log() ).'</div>';

	require_once( YOURLS_INC.'/functions-html.php' );
	yourls_html_head( 'httpBL', 'ALERT!' );	//html, body, and a div tags are inclided
	yourls_html_logo();
	echo <<<HTML
	<div style="padding:15px 0px 0px 0px;" >
			<div style="display: inline-block; text-align: left">
				<h2 class="text-danger" style="text-align:center;"><img src="$img" width="30" height="30"/> Forbidden: Access Denied <img src="$img" width="30" height="30"/></h2>
				</br>
				<p>Your IP: <strong>$ip</strong>, has been flagged by <a href='https://www.projecthoneypot.org' target='_blank'>Project Honey Pot</a> due to the following: 
				<ul>
					<li>Behavior Type: <strong>$typemeaning</strong></li>
					<li>Threat Level: <strong>$threat</strong></li>
				</ul>
				<p>Information regarding threat levels can be found <a href="https://www.projecthoneypot.org/threat_info.php" target="_blank">here</a>.</p>
				$greyList
				<p style="display:none;">Otherwise, please have fun with <a href="http://planetozh.com/smelly.php">this page</a></p>
				<p>Thank you.</p>
			</div>
	</div>
</div>
<footer id="footer" role="contentinfo"><p>
	<script type="text/javascript">
		function setcookie( name, value, expires, path, domain, secure ) {
			// set time, it's in milliseconds
			var today = new Date();
			today.setTime( today.getTime() );

			if ( expires ) {
				expires = expires * 1000 * 60 * 60 * 24;
			}
			var expires_date = new Date( today.getTime() + (expires) );

			document.cookie = name + "=" +escape( value ) +
			( ( expires ) ? ";expires=" + expires_date.toGMTString() : "" ) + 
			( ( path ) ? ";path=" + path : "" ) + 
			( ( domain ) ? ";domain=" + domain : "" ) +
			( ( secure ) ? ";secure" : "" );
		}	
		function letmein() {
			setcookie('notabot','true',1,'/', '', '');
			location.reload(true);
		}
	</script>
	$footer
</footer>
$debug
</body>
</html>
HTML;
	die();
}
/*
 *
 *	Database Functions
 *
 *
*/

// temporary update DB script
if (!defined( 'HTTPBL_DB_UPDATE' ))
	define( 'HTTPBL_DB_UPDATE', false );
if( HTTPBL_DB_UPDATE )
	yourls_add_action( 'plugins_loaded', 'httpbl_update_DB' );
function httpbl_update_DB () {
	global $ydb;
	$tables =  array( 'httpBL_log' , 'httpBL_wl');
	foreach( $tables as $table ) {
		if ( YOURLS_DB_PREFIX ) {
			try {
				$sql = "DESCRIBE `".YOURLS_DB_PREFIX . $table."`";
				$fix = $ydb->fetchAffected($sql);
			} catch (PDOException $e) {
				$sql = "RENAME TABLE `".$table."` TO  `".YOURLS_DB_PREFIX.$table."`";
				$fix = $ydb->fetchAffected($sql);
			}
			
			$table = YOURLS_DB_PREFIX . $table;
		}
		
		try {
		    	$sql = "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
		    		WHERE TABLE_NAME = `".$table."`
		    		AND ENGINE = 'INNODB' LIMIT 1";
		    	$fix = $ydb->fetchAffected($sql);
	    	} catch (PDOException $e) {
			$sql = "ALTER TABLE `".$table."` ENGINE = INNODB;";
			$fix = $ydb->fetchAffected($sql);
		}
	}
}
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
		$table = YOURLS_DB_PREFIX . "httpBL_log";
		$table_httpBL_log  = "CREATE TABLE IF NOT EXISTS `".$table."` (";
		$table_httpBL_log .= "timestamp timestamp NOT NULL default CURRENT_TIMESTAMP, ";
		$table_httpBL_log .= "action varchar(9) NOT NULL, ";
		$table_httpBL_log .= "ip varchar(255) NOT NULL, ";
		$table_httpBL_log .= "type varchar(50) NOT NULL, ";
		$table_httpBL_log .= "threat varchar(3) NOT NULL, ";
		$table_httpBL_log .= "activity varchar(255) NOT NULL, ";
		$table_httpBL_log .= "page varchar(255) NOT NULL, ";
		$table_httpBL_log .= "ua varchar(255) NOT NULL, ";
		$table_httpBL_log .= "PRIMARY KEY (timestamp) ";
		$table_httpBL_log .= ") ENGINE=INNODB DEFAULT CHARSET=latin1;";
		$tables = $ydb->fetchAffected($table_httpBL_log);

		yourls_update_option('httpBL_init_log', time());
		$init_log = yourls_get_option('httpBL_init_log');
		if ($init_log === false)
			die("Unable to properly enable http:BL due an apparent problem with the log database.");
	}
	
	// Whitelist table
	$init_wl = yourls_get_option('httpBL_init_wl');
	if ($init_wl === false) {
		// Create the init value
		yourls_add_option('httpBL_init_wl', time());
		// Create the flag table
		$table = YOURLS_DB_PREFIX . "httpBL_wl";
		$table_httpBL_wl  = "CREATE TABLE IF NOT EXISTS `".$table."` (";
		$table_httpBL_wl .= "timestamp timestamp NOT NULL default CURRENT_TIMESTAMP, ";
		$table_httpBL_wl .= "ip varchar(255) NOT NULL, ";
		$table_httpBL_wl .= "notes varchar(255) NOT NULL, ";
		$table_httpBL_wl .= "PRIMARY KEY (timestamp) ";
		$table_httpBL_wl .= ") ENGINE=INNODB DEFAULT CHARSET=latin1;";
		$tables = $ydb->fetchAffected($table_httpBL_wl);
		
		yourls_update_option('httpBL_init_wl', time());
		$init_wl = yourls_get_option('httpBL_init_wl');
		if ($init_wl === false)
			die("Unable to properly enable http:BL due an apparent problem with the whitelist database.");
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
			$table = YOURLS_DB_PREFIX . "httpBL_log";
			$sql = "DROP TABLE IF EXISTS $table";
			$ydb->fetchAffected($sql);
		}
	}
	// Whitelist table
	$httpBL_table_drop_wl = yourls_get_option('httpBL_table_drop_wl');
	if ( $httpBL_table_drop_wl !== "false" ) {
		global $ydb;
		$init_wl = yourls_get_option('httpBL_init_wl');
		if ($init_wl !== false) {
			yourls_delete_option('httpBL_init_wl');
			$table = YOURLS_DB_PREFIX . "httpBL_wl";
			$sql = "DROP TABLE IF EXISTS $table";
			$ydb->fetchAffected($sql);
		}
	}
}
/*
 *
 *	API
 *
 * action=httpBL-WL
 *
 * Optional:
 * notes='STRING'
 *
 * Alternate:
 * deleteIP='IP_ADDRESS'
 *
*/
// This funtion exposes an API to check and whitelist an IP (think cron)
yourls_add_filter( 'api_action_httpBL-WL', 'httpBL_ip_API' );
function httpBL_ip_API() {
	// only authorized users
	$auth = yourls_is_valid_user();
	if( $auth !== true ) {
		$format = ( isset($_REQUEST['format']) ? $_REQUEST['format'] : 'xml' );
		$callback = ( isset($_REQUEST['callback']) ? $_REQUEST['callback'] : '' );
		yourls_api_output( $format, array(
			'simple' => $auth,
			'message' => $auth,
			'errorCode' => 403,
			'callback' => $callback,
		) );
	}

	// Stripping an IP of WL status
	if( isset ( $_REQUEST['deleteIP'] ) ) {
		$ip = $_REQUEST['deleteIP'];
		// Is it in the db?
		if( httpBL_wl_chk($ip) ) {
			// try to remove it
			global $ydb;
			$table = YOURLS_DB_PREFIX . 'httpBL_wl';
			$binds = array('ip' => $ip);
			$sql = "DELETE FROM `$table`  WHERE ip=:ip";
			$delete = $ydb->fetchAffected($sql, $binds);

			if( $delete ) {
				// Success
				return array(
					'statusCode' => 200,
					'code'		 => 1,
					'simple'     => "IP removed from whitelist..",
					'message'    => 'IP_status: removed',
				);
			} else {
				// DB Failure
				return array(
					'statusCode' => 500,
					'code'		 => -1,
					'simple'     => "Unknown error: IP not removed",
					'message'    => 'Unknwon error',
				);
			}
		} else { 
			// Fail: MIA
			return array(
				'statusCode' => 404,
				'code'		 => 0,
				'simple'     => "IP not found in whitelist..",
				'message'    => 'IP_status: not found',
			);
		}
	}

	$ip = yourls_get_ip();
	$wl = httpBL_wl_chk($ip);

	if($wl) {
		// no update requried
		return array(
			'statusCode' => 200,
			'code'		 => 0,
			'simple'     => "This IP is already in the whitelist. Nothing to do here.",
			'message'    => 'IP_status: already listed',
		);
	} else {
		// prepare notes
		$notes = ( isset( $_REQUEST['notes'] ) ? $_REQUEST['notes'] : 'Added via API' );

		global $ydb;
		$table = YOURLS_DB_PREFIX . 'httpBL_wl';
		$binds = array('ip' => $ip, 'notes' => $notes);
		$sql = "REPLACE INTO `$table`  (ip, notes) VALUES (:ip, :notes)";
		$insert = $ydb->fetchAffected($sql, $binds);
		if ($insert) {
			// Success
			return array(
				'statusCode' => 200,
				'code'		 => 1,
				'simple'     => "$ip whitelisted",
				'message'    => 'IP_status: updated',
			);
		} else {
			// DB Failure
			return array(
				'statusCode' => 500,
				'code'		 => -1,
				'simple'     => "Unknown error: IP not inserted",
				'message'    => 'Unknwon error',
			);
		}
	}
}
?>
