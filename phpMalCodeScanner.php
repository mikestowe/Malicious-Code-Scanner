<?php
/*
Name: php Malicious Code Scanner
Original code URI: http://www.mikestowe.com/phpmalcode
URI: https://github.com/mikeybeck/Malicious-Code-Scanner
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks,
the eval( base64_decode() ) attack...
Version: 1.3.2 alpha
Authors: Michael Stowe, Phil Emerson, Mikey Beck
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
 */

// Verbose Output
define('VERBOSE_OUTPUT', false);
// Set to your email:
define('SEND_EMAIL_ALERTS_TO', 'youremail@example.com');
// Set to true to send results to the email address above
define('SEND_EMAIL', true);
// Set to true to display the results to the console (or log if you're redirecting the output)
define('DISPLAY_RESULTS', true);
// Set to true if you wish to check each file for unsually long lines (a common feature of injections).
// Note - this will slow things down considerably!
define('DETECT_LONG_LINES', false);
// Threshold to trigger the recognition of a long line
define('LONG_LINE_THRESHOLD', 350);
// Indicate which files to match (this prevents checking of image files, PDFs etc)
define('FILES_TO_MATCH', '#\.(php|php4|php5|phtml|html|htaccess)#');
// Ignore symlinked folders
define('IGNORE_LINK', true);
// Set to true to check some Wordpress specific stuff
define('WORDPRESS', true);
// Password protect page
define('PASSWORD', 'mysupersecretpassword');

############################################ START CLASS

class PhpMalCodeScan
{
    public $infected_files = [];
    public $scanned_dir = '';
    private $scanned_files = [];
    private $scan_patterns = [
        '/if\(isset\($_GET\[[a-z][0-9][0-9]+/i',
        '/eval\(base64/i',
        '/eval\(\$./i',
        '/[ue\"\'];\$/',
        '/;@ini/i',
        '/((?<![a-z0-9_])eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[)))|(\$_COOKIE\[[\'"a-z0-9_]+\]\()/i',
        '/(\\x[a-z0-9]{1,3}\\x[a-z0-9]{1,3})|(chr\([0-9]{1,3}\)\.chr\([0-9]{1,3}\))/i',
        '/\) \% 3;if \(/',
        '/=\$GLOBALS;\${"\\\/'
    ];

    public function __construct()
    {
        $do_scan = true;
        if (!$this->isCommandLineInterface()) {
            $pass = $_GET['pass'] ?? '';
            if ($pass !== PASSWORD) {
                die();
            }
            // Get list of files & directories up one level
            $dirs = scandir(dirname(__FILE__) . '/..');
?>
            <form name='dirselectform' action='phpMalCodeScanner.php?pass=<?php echo $pass ?>' method='POST'>
                <select name='dirselect'>
<?php
                foreach ($dirs as $dir) {
                    echo dirname(__FILE__) . '/../' . $dir;
                    if (is_dir(dirname(__FILE__) . '/../') . $dir) {
?>
                    <option value="<?php echo $dir ?>"><?php echo $dir ?></option>
<?php
                    }
                }
?>
                </select>
                <input type='submit'>
            </form>
<?php
            $do_scan = false;
            if (isset($_POST['dirselect'])) {
                $dir = '/../' . $_POST['dirselect'];
                $this->$scanned_dir = $dir;
                $do_scan = true;
            }
        }

        if ($do_scan) {
            $this->scan(dirname(__FILE__) . ($dir ?? ''));
            $this->sendalert();
        }
    }

    private function isCommandLineInterface()
    {
        return (php_sapi_name() === 'cli');
    }

    private function scan($dir)
    {
        $this->scanned_files[] = $dir;
        $files = scandir($dir);

        if (!is_array($files)) {
            throw new Exception('Unable to scan directory ' . $dir . '.
    Please make sure proper permissions have been set.');
        }

        foreach ($files as $file) {
            if (
                is_file($dir . '/' . $file) && !in_array($dir . '/' . $file, $this->scanned_files) &&
                preg_match(FILES_TO_MATCH, $file)
            ) {
                if (VERBOSE_OUTPUT) {
                    print "\nChecking file: $dir/$file";
                }
                $this->check(file_get_contents($dir . '/' . $file), $dir . '/' . $file);
            } elseif (is_dir($dir . '/' . $file) && substr($file, 0, 1) != '.') {
                if (IGNORE_LINK && is_link($dir . '/' . $file)) {
                    continue;
                }
                $this->scan($dir . '/' . $file);
            }
        }
    }

    private function check($contents, $file)
    {
        $line_ending = $this->lineEnding();
        $this->scanned_files[] = $file;
        $patterns = '';
        foreach ($this->scan_patterns as $key => $pattern) {
            if (preg_match($pattern, $contents)) {
                if ($file !== __FILE__) {
                    $patterns .= $pattern;
                }
            }
        }
        if (!empty($patterns)) {
            $this->infected_files[] = [
                'file' => $file,
                'patterns_matched' => $this->isCommandLineInterface() ? $patterns : highlight_string($patterns, true)
            ];
        }

        if (WORDPRESS) {
            $filename = basename($file);
            if (($filename === 'wp-config.php' || $filename === 'settings.php' || $filename === 'index.php') &&
                preg_match('/@include ("|\')\\\|#s@/', $contents)
            ) {
                $this->infected_files[] = [
                    'file' => $file,
                    'patterns_matched' => ' [possibly infected WP file]'
                ];
                return true;
            }
        }
        //  If checking for long lines is not enabled, leave the function now
        if (!DETECT_LONG_LINES) {
            return false;
        }

        // Detect long lines must be enabled - split the file and check how long each line is.
        $buffer = preg_split('#\r\n|\n|\r#', trim($contents));
        $count = 1;
        foreach ($buffer as $line) {
            // Have we found a line longer than the threshold?
            if (strlen($line) > LONG_LINE_THRESHOLD) {
                // Yes - add the file to the infected files list
                $this->infected_files[] = $file . "\nLong line found on line $count\n    ---    " .
                    substr($line, -100) . "\n";
                // Clean up.
                $buffer = null;
                unset($buffer);
                // As we've already found a long line, there's no need to check for others.
                return true;
            }
            $count++;
        }
        // Nothing detected in the current file - return false.
        return false;
    }

    private function lineEnding()
    {
        if ($this->isCommandLineInterface()) {
            return "\n";
        }
        return '<br>';
    }

    private function sendalert()
    {
        $line_ending = $this->lineEnding();
        if (count($this->infected_files) != 0) {
            $message = "== MALICIOUS CODE FOUND == \n\n";
            $message .= "The following " . count($this->infected_files) . " files appear to be infected: " .
                $line_ending . $line_ending;
            foreach ($this->infected_files as $inf) {
                $message .= $line_ending . "  -  " . $inf['file'] . $inf['patterns_matched'] . $line_ending;
            }
            if (DISPLAY_RESULTS) {
                print $line_ending . "$message";
            }
            if (SEND_EMAIL) {
                mail(SEND_EMAIL_ALERTS_TO, 'Malicious Code Found!', $message, 'FROM:');
            }
        } else {
            print 'No infected files found in ' . $this->$scanned_dir;
        }
    }
}

############################################ INITIATE CLASS

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)

new PhpMalCodeScan;
