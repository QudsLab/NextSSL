<?php
function cache_gen($file){
    $base = $_SERVER['DOCUMENT_ROOT'] . '/' . $file;
    return md5(file_get_contents($base));
}
function linkGen($file){
    $server_url = 'https://' . $_SERVER['SERVER_NAME'] . '/' . $file;
    return $server_url;
}
function cprint($file){
    echo linkGen($file) . '?v=' . cache_gen($file);
}
