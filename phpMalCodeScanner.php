<?php
/*
Plugin Name: php Malicious Code Scanner
Plugin URI: http://www.mikestowe.com/phpmalcode
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Version: 1.0 alpha
Author: Michael Stowe
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
*/


// Set to your email:
define('SEND_EMAIL_ALERTS_TO','youremail@example.com');


############################################ START CLASS


class phpMalCodeScan {

	public $infected_files = array();
	private $scanned_files = array();
	
	
	function __construct() {
		$this->scan(getcwd());
		$this->sendalert();
	}
	
	
	function scan($dir) {
		$this->scanned_files = $dir;
		$files = scandir($dir);
		foreach($files as $file) {
			if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
				$this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
			} elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
				$this->scan($dir.'/'.$file);
			}
		}
	}
	
	
	function check($contents,$file) {
		$this->scanned_files = $file;
		if(preg_match('/eval\(base64/i',$contents) || preg_match('/eval\($_/i',$contents)) {
			$this->infected_files[] = $file;
		}
	}


	function sendalert() {
		if(count($this->infected_files) != 0) {
			$message = "== MALICIOUS CODE FOUND == \n\n";
			$message .= "The following files appear to be infected: \n";
			foreach($this->infected_files as $inf) {
				$message .= "  -  $inf \n";
			}
			mail(SEND_EMAIL_ALERTS_TO,'Malicious Code Found!',$message,'FROM:');
		}
	}


}


############################################ INITIATE CLASS

new phpMalCodeScan;


?>