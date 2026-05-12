<?php
include $_SERVER['DOCUMENT_ROOT'] . '/common/resp.php';
// =========================================
// Algo Data Index — site/data/index.php
// Loads all category data files and merges
// into a single $data array for API use.
// =========================================
header('Content-Type: application/json');
$files = [
    'a' => 'Encoding & Checksum',
    'b' => 'Hash / Digest / XOF',
    'c' => 'Password KDFs',
    'd' => 'Symmetric Block Ciphers',
    'e' => 'Stream Ciphers',
    'f' => 'Block Cipher Modes',
    'g' => 'AEAD Algorithms',
    'h' => 'MAC Algorithms',
    'i' => 'Key Derivation Functions',
    'j' => 'Key Agreement / KEM',
    'k' => 'Digital Signatures',
    'l' => 'PQ Digital Signatures',
    'm' => 'Stateful Hash Signatures',
    'n' => 'Threshold / MPC',
    'o' => 'Lightweight Crypto',
    'p' => 'DRBG / RNG',
    'q' => 'ZK Proofs / HE',
    'r' => 'Protocol Primitives',
    's' => 'PKI / Certificates',
    't' => 'Hardware / HSM / TEE',
    'u' => 'Verifiable Delay Functions',
    'v' => 'Advanced Primitives',
];

$category = isset($_GET['category']) ? $_GET['category'] : '';
if (!array_key_exists($category, $files)) {
    responder('error', 'Invalid category', [], [], 400);
}
if ($category == 'a') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/a.php'; /* a.php have $data_a var with it's algo */ $data = $data_a;define('DATA', $data_a);}
if ($category == 'b') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/b.php'; /* b.php have $data_b var with it's algo */ $data = $data_b;define('DATA', $data_b);}
if ($category == 'c') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/c.php'; /* c.php have $data_c var with it's algo */ $data = $data_c;define('DATA', $data_c);}
if ($category == 'd') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/d.php'; /* d.php have $data_d var with it's algo */ $data = $data_d;define('DATA', $data_d);}
if ($category == 'e') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/e.php'; /* e.php have $data_e var with it's algo */ $data = $data_e;define('DATA', $data_e);}
if ($category == 'f') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/f.php'; /* f.php have $data_f var with it's algo */ $data = $data_f;define('DATA', $data_f);}
if ($category == 'g') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/g.php'; /* g.php have $data_g var with it's algo */ $data = $data_g;define('DATA', $data_g);}
if ($category == 'h') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/h.php'; /* h.php have $data_h var with it's algo */ $data = $data_h;define('DATA', $data_h);}
if ($category == 'i') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/i.php'; /* i.php have $data_i var with it's algo */ $data = $data_i;define('DATA', $data_i);}
if ($category == 'j') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/j.php'; /* j.php have $data_j var with it's algo */ $data = $data_j;define('DATA', $data_j);}
if ($category == 'k') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/k.php'; /* k.php have $data_k var with it's algo */ $data = $data_k;define('DATA', $data_k);}
if ($category == 'l') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/l.php'; /* l.php have $data_l var with it's algo */ $data = $data_l;define('DATA', $data_l);}
if ($category == 'm') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/m.php'; /* m.php have $data_m var with it's algo */ $data = $data_m;define('DATA', $data_m);}
if ($category == 'n') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/n.php'; /* n.php have $data_n var with it's algo */ $data = $data_n;define('DATA', $data_n);}
if ($category == 'o') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/o.php'; /* o.php have $data_o var with it's algo */ $data = $data_o;define('DATA', $data_o);}
if ($category == 'p') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/p.php'; /* p.php have $data_p var with it's algo */ $data = $data_p;define('DATA', $data_p);}
if ($category == 'q') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/q.php'; /* q.php have $data_q var with it's algo */ $data = $data_q;define('DATA', $data_q);}
if ($category == 'r') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/r.php'; /* r.php have $data_r var with it's algo */ $data = $data_r;define('DATA', $data_r);}
if ($category == 's') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/s.php'; /* s.php have $data_s var with it's algo */ $data = $data_s;define('DATA', $data_s);}
if ($category == 't') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/t.php'; /* t.php have $data_t var with it's algo */ $data = $data_t;define('DATA', $data_t);}
if ($category == 'u') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/u.php'; /* u.php have $data_u var with it's algo */ $data = $data_u;define('DATA', $data_u);}
if ($category == 'v') {include $_SERVER['DOCUMENT_ROOT'] . '/api/db/v.php'; /* v.php have $data_v var with it's algo */ $data = $data_v;define('DATA', $data_v);}
$algo = isset($_GET['algo']) ? $_GET['algo'] : '';
if (!empty($algo)) {
    $found = false;
    $data_new = isset($data['new']) ? $data['new'] : [];
    foreach ($data_new as $item) {
        if ($item['uuid'] === $algo) {
            responder('success', 'Algorithm found', $item);
        }
    }
    $data_legacy = isset($data['legacy']) ? $data['legacy'] : [];
    foreach ($data_legacy as $item) {
        if ($item['uuid'] === $algo) {
            responder('success', 'Algorithm found', $item);
        }
    }
    $data_active = isset($data['active']) ? $data['active'] : [];
    foreach ($data_active as $item) {
        if ($item['uuid'] === $algo) {
            responder('success', 'Algorithm found', $item);
        }
    }
}
responder('error', 'Algorithm not found', [], []);