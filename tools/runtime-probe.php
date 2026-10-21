<?php
/* Temporary administrative probe, PHP 7.3+; remove it after validation.
 * The random secret lives OUTSIDE the web root at /etc/php-cve-audit.token.
 * No POST, file upload, session creation, memory-exhaustion or exploit test.
 */
header('Cache-Control: no-store, private');
header('Content-Type: text/plain; charset=us-ascii');
$tokenFile = '/etc/php-cve-audit.token';
if (!is_readable($tokenFile)) { http_response_code(404); exit; }
$expected = trim(file_get_contents($tokenFile));
$provided = isset($_SERVER['HTTP_X_PHP_AUDIT_TOKEN']) ? $_SERVER['HTTP_X_PHP_AUDIT_TOKEN'] : '';
if (!preg_match('/\A[0-9a-fA-F]{64}\z/', $expected) || !hash_equals($expected, $provided)) {
    http_response_code(404); exit;
}
$nonce = isset($_GET['nonce']) ? $_GET['nonce'] : '';
if (!is_string($nonce) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce)) {
    http_response_code(400); exit;
}
$path = ''; $mappedInode = ''; $consistent = '0'; $deleted = '0';
if (PHP_SAPI === 'apache2handler' && is_readable('/proc/self/maps')) {
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        $parts = preg_split('/\s+/', trim($line), 6);
        if (count($parts) !== 6) { continue; }
        $candidate = $parts[5];
        $isDeleted = substr($candidate, -10) === ' (deleted)';
        if ($isDeleted) { $candidate = substr($candidate, 0, -10); }
        if (!preg_match('/\Alibphp[0-9.]*\.so\z/', basename($candidate))) { continue; }
        $path = $candidate; $mappedInode = $parts[4];
        $deleted = $isDeleted ? '1' : '0';
        clearstatcache(true, $path);
        if (!$isDeleted && is_file($path) && (string)fileinode($path) === $mappedInode) {
            $consistent = '1';
        }
        break;
    }
} elseif (PHP_SAPI !== 'apache2handler' && is_file(PHP_BINARY)) {
    $path = realpath(PHP_BINARY);
    if (is_readable('/proc/self/exe') &&
        (string)fileinode('/proc/self/exe') === (string)fileinode($path)) {
        $consistent = '1';
    }
}
$extensions = get_loaded_extensions(); sort($extensions);
$guard = function_exists('hp_uploadprogress_guard_status') ? hp_uploadprogress_guard_status() : array();
$info = array(
    'version'=>PHP_VERSION, 'sapi'=>PHP_SAPI, 'pid'=>(string)getmypid(),
    'php_zts'=>(string)(int)PHP_ZTS, 'php_debug'=>(string)(int)PHP_DEBUG,
    'php_word_bytes'=>(string)PHP_INT_SIZE,
    'nonce'=>$nonce, 'php_ini'=>(string)php_ini_loaded_file(),
    'scanned_ini'=>(string)php_ini_scanned_files(),
    'memory_limit'=>(string)ini_get('memory_limit'),
    'upload_progress'=>(string)ini_get('session.upload_progress.enabled'),
    'post_max_size'=>(string)ini_get('post_max_size'),
    'multipart_parts_limit'=>(string)ini_get('max_multipart_body_parts'),
    'extensions'=>implode(',', $extensions),
    'image_path'=>$path, 'image_consistent'=>$consistent,
    'image_sha256'=>($consistent === '1' && is_readable($path)) ? hash_file('sha256', $path) : '',
    'mapped_inode'=>$mappedInode, 'deleted_mapping'=>$deleted
);
foreach ($guard as $key => $value) { $info['guard_' . $key] = is_bool($value) ? ($value ? '1' : '0') : (string)$value; }
$info['guard_mapping_consistent'] = '0';
$info['guard_module_sha256'] = '';
$info['mbstring_encoding_translation'] = (string)ini_get('mbstring.encoding_translation');
if (is_readable('/proc/self/maps')) {
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        $parts = preg_split('/\s+/', trim($line), 6);
        if (count($parts) !== 6 || basename($parts[5]) !== 'hp_uploadprogress_guard.so') { continue; }
        $modulePath = $parts[5];
        clearstatcache(true, $modulePath);
        if (is_readable($modulePath) && (string)fileinode($modulePath) === $parts[4]) {
            $info['guard_mapping_consistent'] = '1';
            $info['guard_module_sha256'] = hash_file('sha256', $modulePath);
        }
        break;
    }
}
echo "PHP_CVE_AUDIT_V1\n";
foreach ($info as $key=>$value) { echo $key, ':', base64_encode($value), "\n"; }
