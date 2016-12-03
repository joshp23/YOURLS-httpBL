<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Options display html
// Copyright (c) 2016, Josh Panter <joshu@unfettered.net>

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
?>
	<link rel="stylesheet" href="/css/infos.css?v=1.7.2" type="text/css" media="screen" />
	<script src="/js/infos.js?v=1.7.2" type="text/javascript"></script>

	<div id="wrap">
		<div id="tabs">

			<div class="wrap_unfloat">
				<ul id="headers" class="toggle_display stat_tab">
					<li class="selected"><a href="#stat_tab_behavior"><h2>http:BL Config</h2></a></li>
					<li><a href="#stat_tab_httpBL_wl"><h2>White List</h2></a></li>
					<li style="display:%log_vis%;"><a href="#stat_tab_logs"><h2>Logs</h2></a></li>
				</ul>
			</div>

			<div id="stat_tab_behavior" class="tab">

				<form method="post">
					<h3>Project Honeypot API Key</h3>

					<p>In order to use http:BL you need to have a Project Honeypot API key. For information on how to become a member of the project and get yourself a free key, please click <a href="https://www.projecthoneypot.org/" target="_blank">here</a>. Otherwise, please enter your key below.</p>
					<p><label for="httpBL_api_key">Your Key  </label> <input type="text" size=20 id="httpBL_api_key" name="httpBL_api_key" value="%httpBL_api_key%" /></p>

					<h3>Block Page</h3>
					<div class="checkbox">
					  <label>
						<input name="httpBL_cstm_block_tgl" type="hidden" value="false" />
						<input name="httpBL_cstm_block_tgl" type="checkbox" value="true" %url_chk% >Use custom block page URL?
					  </label>
					</div>
					<div>
						<p>Setting the above option without setting this will fall back to default behavior.</p>
						<p><label for="httpBL_cstm_block">Enter custome block page URL here</label> <input type="text" size=40 id="httpBL_cstm_block" name="httpBL_cstm_block" value="%httpBL_cstm_block%" /></p>
					</div>
					
					<h3>Table Management</h3>
					
					<p>Would you like to keep logs?</p>
					<div class="checkbox">
					  <label>
						<input name="httpBL_log_blocked" type="hidden" value="false" />
						<input name="httpBL_log_blocked" type="checkbox" value="true" %lb_chk% > Log visitor block events?
					  </label>
					</div>
					<div class="checkbox">
					  <label>
						<input name="httpBL_log_unblocked" type="hidden" value="false" />
						<input name="httpBL_log_unblocked" type="checkbox" value="true" %lub_chk% > Log visitor unblock events (passed cookie)?
					  </label>
					</div>
					
					<p>This plugin automatically drops its databse tables when disabled. You can override this here.</p>
					<div class="checkbox">
					  <label>
						<input name="httpBL_table_drop_log" type="hidden" value="false" />
						<input name="httpBL_table_drop_log" type="checkbox" value="true" %drop_chk_log% > Drop the logs when disabled?
					  </label>
				        </div>
				        <div class="checkbox">
					  <label>
						<input name="httpBL_table_drop_wl" type="hidden" value="false" />
						<input name="httpBL_table_drop_wl" type="checkbox" value="true" %drop_chk_wl% > Drop the white list when disabled?
					  </label>
					</div>
					
					<input type="hidden" name="nonce" value="%nonce%" />
					<p><input type="submit" value="Submit" /></p>
				</form>
			</div>
