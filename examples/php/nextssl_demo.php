<?php
// NextSSL from PHP (FFI extension). One file: a small binding plus a demo per algorithm kind.
//
//   php -d ffi.enable=1 nextssl_demo.php                  list all algorithms
//   php -d ffi.enable=1 nextssl_demo.php --list kem       list one kind
//   php -d ffi.enable=1 nextssl_demo.php sha256           run the demo for an algorithm (safe API)
//   php -d ffi.enable=1 nextssl_demo.php --root md5       other tiers need --root
//   php -d ffi.enable=1 nextssl_demo.php --info ml-kem-768
//
// The library is found through NEXTSSL_LIB or ../../target/{release,debug}. Every operation is a
// call into the NextSSL C ABI; nothing here implements cryptography.

declare(strict_types=1);

const HEADER = <<<'H'
typedef struct nextssl_in { const uint8_t *ptr; size_t len; } nextssl_in;
typedef struct nextssl_out { uint8_t *ptr; size_t cap; size_t len; } nextssl_out;
const char *nextssl_version(void);
uint32_t nextssl_abi_version(void);
const char *nextssl_error_message(int32_t code);
int32_t nextssl_algorithms_json(const char *kind, nextssl_out *out);
int32_t nextssl_algorithm_info_json(const char *alg, nextssl_out *out);
int32_t nextssl_hash_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_root_hash_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_xof(const char *alg, const char *params, const nextssl_in *data, size_t want, nextssl_out *out);
int32_t nextssl_root_xof(const char *alg, const char *params, const nextssl_in *data, size_t want, nextssl_out *out);
int32_t nextssl_checksum(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_root_checksum(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_encode_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_root_encode_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_decode_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_root_decode_with(const char *alg, const char *params, const nextssl_in *data, nextssl_out *out);
int32_t nextssl_mac(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *data, size_t tag_len, nextssl_out *out);
int32_t nextssl_root_mac(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *data, size_t tag_len, nextssl_out *out);
int32_t nextssl_mac_verify(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *data, const nextssl_in *tag);
int32_t nextssl_root_mac_verify(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *data, const nextssl_in *tag);
int32_t nextssl_kdf(const char *alg, const char *params, const nextssl_in *ikm, const nextssl_in *salt, const nextssl_in *info, size_t want, nextssl_out *out);
int32_t nextssl_root_kdf(const char *alg, const char *params, const nextssl_in *ikm, const nextssl_in *salt, const nextssl_in *info, size_t want, nextssl_out *out);
int32_t nextssl_aead_seal(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *nonce, const nextssl_in *aad, const nextssl_in *pt, nextssl_out *out);
int32_t nextssl_root_aead_seal(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *nonce, const nextssl_in *aad, const nextssl_in *pt, nextssl_out *out);
int32_t nextssl_aead_open(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *nonce, const nextssl_in *aad, const nextssl_in *ct, nextssl_out *out);
int32_t nextssl_root_aead_open(const char *alg, const char *params, const nextssl_in *key, const nextssl_in *nonce, const nextssl_in *aad, const nextssl_in *ct, nextssl_out *out);
int32_t nextssl_kem_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_root_kem_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_kem_encaps(const char *alg, const char *params, const nextssl_in *pk, nextssl_out *ct, nextssl_out *ss);
int32_t nextssl_root_kem_encaps(const char *alg, const char *params, const nextssl_in *pk, nextssl_out *ct, nextssl_out *ss);
int32_t nextssl_kem_decaps(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *ct, nextssl_out *ss);
int32_t nextssl_root_kem_decaps(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *ct, nextssl_out *ss);
int32_t nextssl_kex_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_root_kex_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_kex_agree(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *peer_pk, nextssl_out *ss);
int32_t nextssl_root_kex_agree(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *peer_pk, nextssl_out *ss);
int32_t nextssl_sign_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_root_sign_keygen(const char *alg, const char *params, nextssl_out *pk, nextssl_out *sk);
int32_t nextssl_sign_detached(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *msg, const nextssl_in *ctx, nextssl_out *sig);
int32_t nextssl_root_sign_detached(const char *alg, const char *params, const nextssl_in *sk, const nextssl_in *msg, const nextssl_in *ctx, nextssl_out *sig);
int32_t nextssl_verify_detached(const char *alg, const char *params, const nextssl_in *pk, const nextssl_in *msg, const nextssl_in *ctx, const nextssl_in *sig);
int32_t nextssl_root_verify_detached(const char *alg, const char *params, const nextssl_in *pk, const nextssl_in *msg, const nextssl_in *ctx, const nextssl_in *sig);
int32_t nextssl_rng_fill(const char *alg, const char *params, size_t want, nextssl_out *out);
int32_t nextssl_root_rng_fill(const char *alg, const char *params, size_t want, nextssl_out *out);
H;

const ERR_BAD_OUTPUT_LEN = 10;
const ERR_AUTH_FAILED = 14;

final class NextSSLError extends RuntimeException
{
    public function __construct(public int $codeNum, string $message, public string $op)
    {
        parent::__construct("$op: $message (code $codeNum)");
    }
}

final class NextSSL
{
    private FFI $ffi;
    /** @var array<int,mixed> keeps CData alive while a call is in flight */
    private array $keep = [];

    public function __construct(string $lib, public bool $root = false)
    {
        $this->ffi = FFI::cdef(HEADER, $lib);
    }

    public function message(int $code): string
    {
        return $this->ffi->nextssl_error_message($code); // const char* arrives as a PHP string
    }

    public function version(): string
    {
        return $this->ffi->nextssl_version();
    }

    public function abiVersion(): int
    {
        return $this->ffi->nextssl_abi_version();
    }

    private function fn(string $op): string
    {
        return ($this->root ? 'nextssl_root_' : 'nextssl_') . $op;
    }

    /** Builds a nextssl_in over a PHP string. The buffer stays alive in $this->keep. */
    private function in(string $bytes): FFI\CData
    {
        $in = $this->ffi->new('nextssl_in');
        $n = strlen($bytes);
        if ($n > 0) {
            $buf = $this->ffi->new("uint8_t[$n]");
            FFI::memcpy($buf, $bytes, $n);
            $this->keep[] = $buf;
            $in->ptr = $this->ffi->cast('uint8_t *', $buf);
        }
        $in->len = $n;
        $this->keep[] = $in;
        return FFI::addr($in);
    }

    /**
     * Calls nextssl_[root_]$op. $sig has one letter per argument before the outputs:
     * t = C string (null allowed), b = bytes (nextssl_in), z = size_t.
     * Returns the list of output byte strings (grown automatically), or the status when $outs = 0.
     *
     * @param array<int,mixed> $args
     * @return array<int,string>|int
     */
    public function call(string $op, string $sig, array $args, int $outs = 1, array $okCodes = [0])
    {
        $name = $this->fn($op);
        $c = [];
        foreach (str_split($sig) as $i => $kind) {
            $a = $args[$i];
            $c[] = match ($kind) {
                't' => $a,
                'b' => $this->in($a),
                'z' => $a,
            };
        }
        $caps = array_fill(0, max($outs, 0), 256);
        while (true) {
            $bufs = [];
            $structs = [];
            foreach ($caps as $i => $cap) {
                $bufs[$i] = $this->ffi->new("uint8_t[$cap]");
                $structs[$i] = $this->ffi->new('nextssl_out');
                $structs[$i]->ptr = $this->ffi->cast('uint8_t *', $bufs[$i]);
                $structs[$i]->cap = $cap;
                $structs[$i]->len = 0;
            }
            $all = $c;
            foreach ($structs as $s) {
                $all[] = FFI::addr($s);
            }
            $rc = $this->ffi->$name(...$all);
            if ($rc === ERR_BAD_OUTPUT_LEN) {
                foreach ($structs as $i => $s) {
                    $caps[$i] = max($s->len, 1);
                }
                continue;
            }
            break;
        }
        $this->keep = [];
        if (!in_array($rc, $okCodes, true)) {
            throw new NextSSLError($rc, $this->message($rc), $op);
        }
        if ($outs === 0) {
            return $rc;
        }
        $res = [];
        foreach ($structs as $i => $s) {
            $res[] = $s->len > 0 ? FFI::string($bufs[$i], $s->len) : '';
        }
        return $res;
    }

    /** Verify-style call: true when valid, false for AUTHENTICATION_FAILED, throws otherwise. */
    public function check(string $op, string $sig, array $args): bool
    {
        return $this->call($op, $sig, $args, 0, [0, ERR_AUTH_FAILED]) === 0;
    }

    public function random(int $n): string
    {
        return $this->call('rng_fill', 'ttz', ['os-entropy', null, $n])[0];
    }

    /** @return array<string,mixed> */
    private function json(string $fnName, ?string $arg): array
    {
        $cap = 1;
        while (true) {
            $buf = $this->ffi->new("uint8_t[$cap]");
            $out = $this->ffi->new('nextssl_out');
            $out->ptr = $this->ffi->cast('uint8_t *', $buf);
            $out->cap = $cap;
            $out->len = 0;
            $rc = $this->ffi->$fnName($arg, FFI::addr($out));
            if ($rc === ERR_BAD_OUTPUT_LEN) {
                $cap = $out->len;
                continue;
            }
            if ($rc !== 0) {
                throw new NextSSLError($rc, $this->message($rc), $fnName);
            }
            return json_decode(FFI::string($buf, $out->len), true, 512, JSON_THROW_ON_ERROR);
        }
    }

    /** @return array<int,array<string,mixed>> */
    public function algorithms(?string $kind = null): array
    {
        return $this->json('nextssl_algorithms_json', $kind)['algorithms'];
    }

    /** @return array<string,mixed> */
    public function info(string $name): array
    {
        return $this->json('nextssl_algorithm_info_json', $name);
    }
}

// ----------------------------------------------------------------------------------------------
// Demo
// ----------------------------------------------------------------------------------------------

const KNOWN_ABC = [
    'sha256' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'sha1' => 'a9993e364706816aba3e25717850c26c9cd0d89d',
    'md5' => '900150983cd24fb0d6963f7d28e17f72',
];

function findLibrary(): string
{
    $env = getenv('NEXTSSL_LIB');
    if ($env) {
        return $env;
    }
    $name = match (PHP_OS_FAMILY) {
        'Windows' => 'nextssl_ffi.dll',
        'Darwin' => 'libnextssl_ffi.dylib',
        default => 'libnextssl_ffi.so',
    };
    foreach (['release', 'debug'] as $profile) {
        $p = __DIR__ . "/../../target/$profile/$name";
        if (is_file($p)) {
            return realpath($p);
        }
    }
    fwrite(STDERR, "libnextssl_ffi not found: build it (cargo build -p nextssl-ffi --release) or set NEXTSSL_LIB\n");
    exit(2);
}

function pick(array $info, string $field, int $prefer): int
{
    $r = $info['sizes'][$field] ?? null;
    return $r ? max($r['min'], min($prefer, $r['max'])) : $prefer;
}

function show(string $label, string $data): void
{
    $h = bin2hex($data);
    printf("  %-14s %s (%d bytes)\n", $label, strlen($h) <= 96 ? $h : substr($h, 0, 96) . '...', strlen($data));
}

function tamper(string $b): string
{
    return chr(ord($b[0]) ^ 1) . substr($b, 1);
}

function yn(bool $b): string
{
    return $b ? 'true' : 'false';
}

function demo(NextSSL $ns, array $info, ?string $p): void
{
    $alg = $info['id'];
    switch ($info['kind']) {
        case 'hash':
            $d = $ns->call('hash_with', 'ttb', [$alg, $p, 'abc'])[0];
            show('digest(abc)', $d);
            $want = KNOWN_ABC[$alg] ?? null;
            echo $want ? '  known answer    ' . (bin2hex($d) === $want ? 'MATCH' : "MISMATCH (expected $want)") . "\n"
                : "  known answer    (none built into this example)\n";
            break;
        case 'xof':
            show('xof(abc,48)', $ns->call('xof', 'ttbz', [$alg, $p, 'abc', 48])[0]);
            break;
        case 'checksum':
            $c = $ns->call('checksum', 'ttb', [$alg, $p, '123456789'])[0];
            show('check', $c);
            if ($alg === 'crc32') {
                echo '  known answer    ' . (bin2hex($c) === 'cbf43926' ? 'MATCH' : 'MISMATCH (expected cbf43926)') . "\n";
            }
            break;
        case 'encoding':
            $raw = "\x00hello, nextssl\xff";
            $e = $ns->call('encode_with', 'ttb', [$alg, $p, $raw])[0];
            echo "  encoded         $e\n";
            echo '  round trip      ' . ($ns->call('decode_with', 'ttb', [$alg, $p, $e])[0] === $raw ? 'OK' : 'FAILED') . "\n";
            break;
        case 'mac':
            $key = $ns->random(pick($info, 'key', 32));
            $tag = $ns->call('mac', 'ttbbz', [$alg, $p, $key, 'abc', 0])[0];
            show('tag', $tag);
            echo '  verify          ' . yn($ns->check('mac_verify', 'ttbbb', [$alg, $p, $key, 'abc', $tag])) . "\n";
            echo '  verify tampered ' . yn($ns->check('mac_verify', 'ttbbb', [$alg, $p, $key, 'abc', tamper($tag)])) . "\n";
            break;
        case 'kdf':
            $ikm = $ns->random(pick($info, 'key', 32));
            show('derived(32)', $ns->call('kdf', 'ttbbbz', [$alg, $p, $ikm, 'salt-16-bytes!!!', 'ctx', 32])[0]);
            break;
        case 'aead':
            $key = $ns->random(pick($info, 'key', 32));
            $nonce = $ns->random(pick($info, 'nonce', 12));
            $ct = $ns->call('aead_seal', 'ttbbbb', [$alg, $p, $key, $nonce, 'header', 'attack at dawn'])[0];
            show('ciphertext', $ct);
            $pt = $ns->call('aead_open', 'ttbbbb', [$alg, $p, $key, $nonce, 'header', $ct])[0];
            echo '  round trip      ' . ($pt === 'attack at dawn' ? 'OK' : 'FAILED') . "\n";
            try {
                $ns->call('aead_open', 'ttbbbb', [$alg, $p, $key, $nonce, 'header', tamper($ct)]);
                echo "  tampered        ACCEPTED (bug!)\n";
            } catch (NextSSLError $e) {
                echo '  tampered        rejected: ' . $e->getMessage() . "\n";
            }
            break;
        case 'kem':
            [$pk, $sk] = $ns->call('kem_keygen', 'tt', [$alg, $p], 2);
            [$ct, $ss] = $ns->call('kem_encaps', 'ttb', [$alg, $p, $pk], 2);
            $ss2 = $ns->call('kem_decaps', 'ttbb', [$alg, $p, $sk, $ct])[0];
            show('public key', $pk);
            show('ciphertext', $ct);
            show('shared secret', $ss);
            echo '  secrets equal   ' . yn($ss === $ss2) . "\n";
            break;
        case 'kex':
            [$pa, $sa] = $ns->call('kex_keygen', 'tt', [$alg, $p], 2);
            [$pb, $sb] = $ns->call('kex_keygen', 'tt', [$alg, $p], 2);
            $s1 = $ns->call('kex_agree', 'ttbb', [$alg, $p, $sa, $pb])[0];
            $s2 = $ns->call('kex_agree', 'ttbb', [$alg, $p, $sb, $pa])[0];
            show('shared secret', $s1);
            echo '  both sides equal ' . yn($s1 === $s2) . "\n";
            break;
        case 'sign':
            [$pk, $sk] = $ns->call('sign_keygen', 'tt', [$alg, $p], 2);
            $sig = $ns->call('sign_detached', 'ttbbb', [$alg, $p, $sk, 'sign this', ''])[0];
            show('public key', $pk);
            show('signature', $sig);
            echo '  verify          ' . yn($ns->check('verify_detached', 'ttbbbb', [$alg, $p, $pk, 'sign this', '', $sig])) . "\n";
            echo '  wrong message   ' . yn($ns->check('verify_detached', 'ttbbbb', [$alg, $p, $pk, 'sign that', '', $sig])) . "\n";
            break;
        case 'rng':
            show('random(16)', $ns->call('rng_fill', 'ttz', [$alg, $p, 16])[0]);
            break;
        default:
            echo "  no demo for kind '{$info['kind']}' in the PHP example (the Python example covers every kind);\n";
            echo '  its C functions are: ' . implode(', ', $info['ops']) . "\n";
    }
}

function listing(NextSSL $ns, ?string $kind): void
{
    $algs = $ns->algorithms($kind);
    printf("%-34s%-14s%-11s%s\n", 'id', 'kind', 'tier', 'access');
    $kinds = [];
    foreach ($algs as $a) {
        printf("%-34s%-14s%-11s%s\n", $a['id'], $a['kind'], $a['tier'], $a['safe_api'] ? 'safe' : 'root');
        $kinds[$a['kind']] = ($kinds[$a['kind']] ?? 0) + 1;
    }
    ksort($kinds);
    printf("\n%d algorithms, ABI v%d, library %s\nkinds: %s\n", count($algs), $ns->abiVersion(), $ns->version(),
        implode(', ', array_map(fn($k, $n) => "$k=$n", array_keys($kinds), $kinds)));
}

function main(array $argv): int
{
    array_shift($argv);
    $root = in_array('--root', $argv, true);
    $argv = array_values(array_filter($argv, fn($a) => $a !== '--root'));
    $params = null;
    if (($i = array_search('--params', $argv, true)) !== false) {
        $params = $argv[$i + 1] ?? null;
        array_splice($argv, $i, 2);
    }
    $ns = new NextSSL(findLibrary(), $root);
    if (!$argv || in_array($argv[0], ['--list', '-l'], true)) {
        listing($ns, $argv[1] ?? null);
        return 0;
    }
    if ($argv[0] === '--info') {
        echo json_encode($ns->info($argv[1]), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
        return 0;
    }
    $info = $ns->info($argv[0]);
    printf("%s  kind=%s  tier=%s  license=%s  api=%s\n", $info['id'], $info['kind'], $info['tier'], $info['license'],
        $info['safe_api'] ? 'safe' : 'root only');
    try {
        demo($ns, $info, $params);
    } catch (NextSSLError $e) {
        echo '  error: ', $e->getMessage(), "\n";
        if ($e->codeNum === 3 && !$root) {
            echo "  this tier is not reachable from the safe API; rerun with --root to accept the risk\n";
        }
        return $e->codeNum;
    }
    return 0;
}

exit(main($argv));
