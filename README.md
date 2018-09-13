# YOURLS-HTTP:BL
An implimentation of Project Honeypot's http:BL for YOURLS

http:BL is a black list service from [Project Honeypot](https://www.projecthoneypot.org) with an API that is trivial to hook into. While other spam management services & plugins, such as [Phishtank](https://github.com/joshp23/YOURLS-Phishtank-2.0), can check outgoing links, content submissions, and re-check old redirects, Project Honeypot's http:BL acts as a gatekeeper, stopping malicious users at the door before they can do any damage.

This plugin can help filter out spam submissions on a YOURLS public interface _and_ on the API. It will redirect any bad IP to an informative and customization friendly block/intercept page written with Bootstrap. If greylisted, any human users will be able to easily set a cookie and access the YOURLS installation. For the API users, it will simply send back an Error 403.

Here are a few of HTTP:BL's features

1. All logs and settings are in the admin interface, no hand editing of any files (unless you want to).
2. Configure threshold levels for blocking and greylisting per threat type (or use defaults for ease of use).
3. Use either native YOURLS style or a custom intercept page for flagged IP's. Edit the template, or redirect to your own URL.
4. Granular log keeping: log only event types that you want, or none at all.
5. Flush the log table and start fresh whenever you want.
6. Self-managing: this plugin will (optionally) drop its tables when deactivated, and will create its own tables on activation.
7. Whitelist IP addressess to skip checks; autodetection and 1-click addition of the current IP.
8. An API for White-List maintanence.

## REQUIREMENTS

1. A working [YOURLS](https://github.com/YOURLS/YOURLS) installation
2. YOURLS mysql user should have CREATE TABLE grants on YOURLS database. See NOTE.
3. A Project Honeypot API Key. ([Look here](https://www.projecthoneypot.org/faq.php#g))

### INSTALLATION

1. Place the httpBL folder in YOURLS/user/plugins/
2. Activate http:BL for Yourls in the Admin interface - sql tables should be made automatically
3. Set options in the HTTP:BL options page. The default options are just fine. Clicking submit on various forms will enter the default values into the sql tables, but null values all fall back to default actions as well.
4. If using a custom URL for blocking, please note the following requests that will be sent to your URL
	- `action` grey or blacklist
	- `ip` the offending IP address
	- `type` the threat type (eg: content spammer)
	- `level` the threat level (0-255)
5. For information regarding the API, see the http:BL page in the Admin area.

#### NOTE: 
In order for this to work on your public page you have to make sure that  
```  
// Start YOURLS engine  
require_once( dirname(__FILE__).'/includes/load-yourls.php' );  
```  
comes before anything else. If you are using the [Sleaky](https://github.com/Flynntes/Sleeky) interface, edit `index.php` to put the above line before  
```  
include 'header.php';
```

#### NOTE:
The sql table may need to be added manually using `httpBL/assets/httpBL.sql`


#### HINT:
Use a script that manages callbacks and stores IP addresses in a flat file to update and delete IP's in the white-list automagically via cron.

### TODO:
1. Add dynamic and randomized honeypot "quicklinks" to all rendered pages - this will likely come in the form of a custom index page, or footer script.

### CREDITS
Scripts used for inspiration and/or copypasta:

1. [OZH's simple http:BL](http://planetozh.com/blog/my-projects/honey-pot-httpbl-simple-php-script/)
2. [YOURLS Interstitial plugin](https://github.com/joelgratcyk/yourls-interstitial-plugin)
3. [YOURLS Complaince](https://github.com/joshp23/YOURLS-Compliance)

===========================

    Copyright (C) 2016 - 2018 Josh Panter

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
