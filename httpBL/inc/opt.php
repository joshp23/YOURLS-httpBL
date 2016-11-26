<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Options display html
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
?>
	<link rel="stylesheet" href="/css/infos.css?v=1.7.2" type="text/css" media="screen" />
	<script src="/js/infos.js?v=1.7.2" type="text/javascript"></script>

	<div id="wrap">

		<div class="sub_wrap">
		<div id="tabs">

			<div class="wrap_unfloat">
				<ul id="headers" class="toggle_display stat_tab">
					<li class="selected"><a href="#stat_tab_behavior"><h2>Core Behavior</h2></a></li>
					<li style="display:%log_vis%;"><a href="#stat_tab_logs"><h2>Logs</h2></a></li>
				</ul>
			</div>

			<div id="stat_tab_behavior" class="tab">

				<form method="post">
					<h3>Project Honeypot API Key</h3>

					<p>In order to use http:BL you need to have a Project Honeypot API key. For information on how to become a member of the project and get yourse;f a free key, please click <a href="https://www.projecthoneypot.org/" target="_blank">here</a>. Otherwise, please enter your key below.</p>
					<p><label for="httpbl_api_key">Your Key  </label> <input type="text" size=60 id="httpbl_api_key" name="httpbl_api_key" value="%httpbl_api_key%" /></p>

					<h3>Block Page</h3>
					<div class="checkbox">
					  <label>
						<input name="httpbl_cstm_block_tgl" type="hidden" value="false" />
						<input name="httpbl_cstm_block_tgl" type="checkbox" value="true" %url_chk% >Use custom block page URL?
					  </label>
					</div>
					<div>
						<p>Setting the above option without setting this will fall back to default behavior.</p>
						<p><label for="httpbl_cstm_block">Enter custome block page URL here</label> <input type="text" size=40 id="httpbl_cstm_block" name="httpbl_cstm_block" value="%httpbl_cstm_block%" /></p>
					</div>
					
					<h3>Log Table Management</h3>
					
					<p>Would you like to keep logs?</p>
					<div class="checkbox">
					  <label>
						<input name="httpbl_log_blocked" type="hidden" value="false" />
						<input name="httpbl_log_blocked" type="checkbox" value="true" %lb_chk% > Log Blocked visitors?
					  </label>
					</div>
					<div class="checkbox">
					  <label>
						<input name="httpbl_log_unblocked" type="hidden" value="false" />
						<input name="httpbl_log_unblocked" type="checkbox" value="true" %lub_chk% > Log Unblocked visitors?
					  </label>
					</div>
					
					<p>This plugin automatically drops its databse table when disabled. You can override this here.</p>
					<div class="checkbox">
					  <label>
						<input name="httpbl_table_drop" type="hidden" value="false" />
						<input name="httpbl_table_drop" type="checkbox" value="true" %drop_chk% > Drop the logs when disabled?
					  </label>
					</div>
					
					<input type="hidden" name="nonce" value="%nonce%" />
					<p><input type="submit" value="Submit" /></p>
				</form>
			</div>

			<div style="display:%log_vis%;" id="stat_tab_logs" class="tab">

				<h3>Empty Log Table</h3>

				<form method="post">
					<div class="checkbox">
					  <label>
						<input name="httpbl_flush_logs" type="hidden" value="no" />
						<input name="httpbl_flush_logs" type="checkbox" value="yes"> Check here and FLUSH! to empty the logs.
					  </label>
					</div>
					<input type="hidden" name="nonce" value="%nonce%" />
					<p><input type="submit" value="FLUSH!" /></p>
				</form>
