<?php

$act = $_GET['act'];

if($act == 'ask_public_key') {
    if(file_exists('server.key')) {
        $keypair = file_get_contents('server.key');
    }
    else {
        $keypair = sodium_crypto_box_keypair();
        file_put_contents('server.key', $keypair);
    }

    $public_key = base64_encode(sodium_crypto_box_publickey($keypair));

    $client_key = null;
    if(file_exists('client.key')) {
        $client_key = file_get_contents('client.key');
    }

    echo json_encode([
        'server_public_key' => $public_key,
        'ask_client_key' => empty($client_key)
    ]);
    exit;
}
elseif($act == 'client_public_key') {
    $json_data = json_decode(file_get_contents('php://input'));
    file_put_contents('client.key', base64_decode($json_data->client_public_key));
    exit;
}
elseif($act == 'data') {
    $keypairServer = file_get_contents('server.key');
    $secretkey = sodium_crypto_box_secretkey($keypairServer);
    $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secretkey, file_get_contents('client.key'));
    $json_data = json_decode(file_get_contents('php://input'));
    $encrypted = base64_decode($json_data->data);
    $nonce = base64_decode($json_data->nonce);
    $decrypted = sodium_crypto_box_open($encrypted, $nonce, $keypair);

    $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
    $data = [
        'encrypted' => base64_encode($encrypted),
        'decrypted' => base64_encode($decrypted)
    ];
    $dataEnc = sodium_crypto_box(json_encode($data), $nonce, $keypair);
    // var_dump(json_encode($data), $dataEnc);
    echo json_encode([
        'data' => base64_encode($dataEnc),
        'nonce' => base64_encode($nonce)
    ]);
    exit;
}