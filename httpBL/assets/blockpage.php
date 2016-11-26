<?php
// Project Honeypot http:BL plugin for Yourls - URL Shortener ~ Block Page Template
// Copyright (c) 2016, Josh Panter

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
header('HTTP/1.0 403 Forbidden');
?>
<html lang="en">
	<head>

		<meta charset="utf-8">
		<title>ALERT!</title>
		<link rel="icon" href="%img%" type="image/png" />

    		<!-- Bootstrap core CSS -- USE LOCAL CACHE
   		<link href="https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/spacelab/bootstrap.min.css" rel="stylesheet" integrity="sha384-L/tgI3wSsbb3f/nW9V6Yqlaw3Gj7mpE56LWrhew/c8MIhAYWZ/FNirA64AVkB5pI" crossorigin="anonymous"> -->
   
		<!-- Bootstrap core CSS -- LOCAL CACHE -->
		<link href="%css%" rel="stylesheet" integrity="sha384-L/tgI3wSsbb3f/nW9V6Yqlaw3Gj7mpE56LWrhew/c8MIhAYWZ/FNirA64AVkB5pI" crossorigin="anonymous">

		<!-- Add extra support of older browsers -->
		<!--[if lt IE 9]>
		<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
		<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
		<![endif]-->
	</head>
	<body>
	  	<div style="padding:15px 0px 0px 0px;" class="col-md-6 col-md-offset-3">
			<div  style="text-align: center;" class="well well-lg">
			    <div style="display: inline-block; text-align: left">

					<h2 class="text-danger" style="text-align:center;"><img src="%img%" width="30" height="30"/> Forbidden: Access Denied <img src="%img%" width="30" height="30"/></h2>
					</br>
					<p>Your IP: <strong>%ip%</strong>, has been flagged by <a href='https://www.projecthoneypot.org' target='_blank'>Project Honey Pot</a> due to the following: 
					<ul>
						<li>Behavior Type: <strong>%typemeaning%</strong></li>
						<li>Threat Level: <strong>%threat%</strong></li>
					</ul>
				
					<p>Information regarding threat levels can be found <a href="https://www.projecthoneypot.org/threat_info.php" target="_blank">here</a>.</p>

					<p>If you <strong>ARE NOT</strong> a bot of any kind, simply <a href="javascript:letmein()">click here</a> to gain access.</p>
					<p style="display:none;">Otherwise, please have fun with <a href="http://planetozh.com/smelly.php">this page</a></p>
				

					<p>Thank you.</p>
	    			</div>
			</div>
		</div>
	</body>
	<footer>
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
	</footer>
</html>
