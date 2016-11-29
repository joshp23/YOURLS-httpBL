CREATE TABLE IF NOT EXISTS `httpBL_log` (
`timestamp` timestamp NOT NULL default CURRENT_TIMESTAMP,
`action` varchar(9) NOT NULL,
`ip` varchar(15) NOT NULL,
`type` varchar(50) NOT NULL,
`threat` varchar(3) NOT NULL,
`activity` varchar(255) NOT NULL,
`page` varchar(20) NOT NULL,
`ua` varchar(50) NOT NULL,
PRIMARY KEY (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `httpBL_wl` (
`timestamp` timestamp NOT NULL default CURRENT_TIMESTAMP,
`ip` varchar(15) NOT NULL,
`notes` varchar(50) NOT NULL,
PRIMARY KEY (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
