<?php
/* Lab only: never deploy this endpoint in a public document root. */
$operation = isset($_GET['op']) ? $_GET['op'] : 'probe';
if ($operation === 'oom') {
    register_shutdown_function(function () { echo 'SHUTDOWN_CALLED'; });
    str_repeat('x', 64 * 1024 * 1024);
    exit;
}
if ($operation === 'fatal') {
    register_shutdown_function(function () { echo 'NORMAL_FATAL_SHUTDOWN'; });
    nonexistent_lab_function();
}
session_start();
$_SESSION['requests'] = isset($_SESSION['requests']) ? $_SESSION['requests'] + 1 : 1;
$files = array();
foreach ($_FILES as $key => $file) {
    $files[$key] = array('name' => $file['name'], 'size' => $file['size'],
        'error' => $file['error'],
        'sha256' => is_string($file['tmp_name']) && is_file($file['tmp_name'])
            ? hash_file('sha256', $file['tmp_name']) : null);
}
header('Content-Type: application/json');
echo json_encode(array('version' => PHP_VERSION, 'sapi' => PHP_SAPI, 'pid' => getmypid(),
    'module' => extension_loaded('hp_uploadprogress_guard'),
    'memory_limit' => ini_get('memory_limit'), 'progress_ini' => ini_get('session.upload_progress.enabled'),
    'progress_present' => isset($_SESSION['upload_progress_lab']),
    'session_requests' => $_SESSION['requests'], 'post' => $_POST, 'files' => $files,
    'basic_user' => isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : null,
    'guard_status' => function_exists('hp_uploadprogress_guard_status') ? hp_uploadprogress_guard_status() : null));
