<?php
/*
Plugin Name: php Malicious Code Scanner
Plugin URI: http://www.mikestowe.com/phpmalcode
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Version: 1.3.1 alpha
Authors: Michael Stowe, Phil Emerson
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
*/
// Verbose Output
define('VERBOSE_OUTPUT',false);
// Set to your email:
define('SEND_EMAIL_ALERTS_TO','youremail@example.com');
// Set to true to send results to the email address above
define('SEND_EMAIL',false);
// Set to true to display the results to the console (or log if you're redirecting the output)
define('DISPLAY_RESULTS',true);
// Set to true if you wish to check each file for unsually long lines (a common feature of injections). Note - this will slow things down considerably!
define('DETECT_LONG_LINES',true);
// Threshold to trigger the recognition of a long line
define('LONG_LINE_THRESHOLD',350);
// Indicate which files to match (this prevents checking of image files, PDFs etc)
define('FILES_TO_MATCH','#\.(php|php4|php5|phtml|html|htaccess)#');
############################################ START CLASS
class phpMalCodeScan {
	public $infected_files = array();
	private $scanned_files = array();


	function __construct() {
		$this->scan(dirname(__FILE__));
		$this->sendalert();
	}


	function scan($dir) {
		$this->scanned_files[] = $dir;
		$files = scandir($dir);

		if(!is_array($files)) {
			throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
		}

		foreach($files as $file) {
			if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files) && preg_match(FILES_TO_MATCH,$file)) {
				if (VERBOSE_OUTPUT) print "\nChecking file: $dir/$file";
				$this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
			} elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
				$this->scan($dir.'/'.$file);
			}
		}
	}


	function check($contents,$file) {
		$this->scanned_files[] = $file;
		if(preg_match('/eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',$contents)) {
			//$this->infected_files[] = $file;
			$this->infected_files[] = $file."\n".str_pad('base64/eval found',' ',30,STR_PAD_LEFT)."\n";
			return true;
		}
		// If checking for long lines is not enabled, leave the function now
		if (!DETECT_LONG_LINES) return false;

		// Detect long lines must be enabled - split the file and check how long each line is.
		$buffer = preg_split('#\r\n|\n|\r#',trim($contents));
		$count = 1;
		foreach($buffer as $line){
			// Have we found a line longer than the threshold?
			if (strlen($line) > LONG_LINE_THRESHOLD){
				// Yes - add the file to the infected files list
				$this->infected_files[] = $file."\nLong line found on line $count\n    ---    ".substr($line,-100)."\n";
				// Clean up.
				$buffer = null; unset($buffer);
				// As we've already found a long line, there's no need to check for others.
				return true;
			}
			$count++;
		}
		// Nothing detected in the current file - return false.
		return false;
	}
	function sendalert() {
		if(count($this->infected_files) != 0) {
			$message = "== MALICIOUS CODE FOUND == \n\n";
			$message .= "The following ".count($this->infected_files)." files appear to be infected: \n\n\n";
			foreach($this->infected_files as $inf) {
				$message .= "$inf \n";
			}
			if (DISPLAY_RESULTS) print "\n$message";
			if (SEND_EMAIL) mail(SEND_EMAIL_ALERTS_TO,'Malicious Code Found!',$message,'FROM:');
		}
	}
}
############################################ INITIATE CLASS
ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)
new phpMalCodeScan;
?>