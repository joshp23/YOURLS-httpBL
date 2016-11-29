<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ white listing functions
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

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
			<p>Any IP listed here will skip http:BL checks. Your currnet IP: <strong>$cip</strong> $a in the white list.</p>			<form method="post">
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
							<td><input type="text" name="ip" placeholder="Leave empty for current ip"></td>
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

// Display page 0.3 - removing from list
function httpBL_wl_remove() {
	global $ydb;

	if( isset($_GET['ip']) ) {
		// @@@FIXME@@@ needs securing against SQL injection !
		$ip = $_GET['ip'];
        	$delete = $ydb->query("DELETE FROM `httpBL_wl` WHERE ip='$ip'");
        	echo '<h3 style="color:green">IP removed from the whitelist. Have a nice day.</h3>';
	}
	// @@@FIXME@@@ This should probably be rewritten to do a redirect to avoid confusion between GET/POST forms
	httpBL_wl_list();
}
