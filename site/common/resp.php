<?php
function responder($status,$message,$data=[],$extra=[], $code=200){
    http_response_code($code);
    $response = [
        'status' => $status,
        'message' => $message,
        'data' => $data
    ];
    if(!empty($extra)){
        $response = array_merge($response, $extra);
    }
    echo json_encode($response);
    exit;
}
