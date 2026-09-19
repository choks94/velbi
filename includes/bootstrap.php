<?php
/*
 * Shared code for the coupon backend (admin/ panel and api/ endpoint).
 *
 * Data lives in small JSON files inside data/. Each file starts with a PHP
 * exit guard, so even if the server ignored data/.htaccess, requesting the
 * file over HTTP would run the guard and return nothing.
 */
declare(strict_types=1);

ini_set('display_errors', '0');
date_default_timezone_set('Europe/Belgrade');

const STORE_GUARD = "<?php exit; ?>\n";

/* ── Config ── */

function app_config(): array
{
    static $config = null;
    if ($config === null) {
        $file   = __DIR__ . '/config.php';
        $loaded = is_file($file) ? require $file : [];
        $config = is_array($loaded) ? $loaded : [];
    }
    return $config;
}

function admin_password_hash(): string
{
    return (string) (app_config()['admin_password_hash'] ?? '');
}

/* ── Storage ── */

function data_dir(): string
{
    return rtrim((string) (app_config()['data_dir'] ?? dirname(__DIR__) . '/data'), '/');
}

function store_path(string $name): string
{
    return data_dir() . '/' . $name . '.php';
}

function store_read(string $name): array
{
    $path = store_path($name);
    if (!is_file($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException("Cannot read store '$name'");
    }
    if (strncmp($raw, STORE_GUARD, strlen(STORE_GUARD)) === 0) {
        $raw = substr($raw, strlen(STORE_GUARD));
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        throw new RuntimeException("Store '$name' is corrupt");
    }
    return $data;
}

/**
 * Read-modify-write under an exclusive lock. $mutate receives the data by
 * reference; its return value is passed through. The file is replaced via
 * rename, so readers never see a half-written store.
 */
function store_update(string $name, callable $mutate)
{
    $dir = data_dir();
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new RuntimeException("Cannot create data directory $dir");
    }
    $lock = fopen("$dir/$name.lock", 'c');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        throw new RuntimeException("Cannot lock store '$name'");
    }
    try {
        $data   = store_read($name);
        $result = $mutate($data);
        $json   = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG);
        $tmp    = "$dir/$name." . bin2hex(random_bytes(6)) . '.tmp.php';
        if ($json === false
            || file_put_contents($tmp, STORE_GUARD . $json . "\n") === false
            || !rename($tmp, store_path($name))) {
            @unlink($tmp);
            throw new RuntimeException("Cannot write store '$name'");
        }
        return $result;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/* ── Coupons ── */
// Stored as a list: [{ "code": "VELBI10", "percent": 10, "active": true, "created_at": "..." }]

const COUPON_MIN_PERCENT = 1;
const COUPON_MAX_PERCENT = 100;

function coupon_normalize(string $code): string
{
    return strtoupper(trim($code));
}

function coupon_code_is_valid(string $code): bool
{
    return preg_match('/^[A-Z0-9_-]{3,32}$/', $code) === 1;
}

function coupon_index(array $coupons, string $code): ?int
{
    foreach ($coupons as $i => $coupon) {
        if ($coupon['code'] === $code) {
            return $i;
        }
    }
    return null;
}

function coupon_find_active(string $code): ?array
{
    $coupons = store_read('coupons');
    $i = coupon_index($coupons, $code);
    return $i !== null && $coupons[$i]['active'] ? $coupons[$i] : null;
}

/* ── Request helpers ── */

function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? $value : '';
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function request_is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}
