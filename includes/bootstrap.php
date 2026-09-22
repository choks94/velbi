<?php
/*
 * Shared code for the coupon backend (admin/ panel and api/ endpoints).
 *
 * Coupons and the anonymous order log for the stats live in the site's MySQL
 * database (hPanel → Databases). The connection details and the admin password
 * hash come from config.php.
 */
declare(strict_types=1);

ini_set('display_errors', '0');
date_default_timezone_set('Europe/Belgrade');

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

/* ── Database ── */

const COUPON_MIN_PERCENT = 1;
const COUPON_MAX_PERCENT = 100;

function db_configured(): bool
{
    $db = app_config()['db'] ?? null;
    return is_array($db) && ($db['name'] ?? '') !== '' && ($db['user'] ?? '') !== '';
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        // Fail fast instead of stalling checkout if MySQL hangs: ATTR_TIMEOUT only covers the
        // TCP connect, this covers every read after it (default is a whole day).
        ini_set('mysqlnd.net_read_timeout', '5');
        $db  = app_config()['db'] ?? [];
        $pdo = new PDO(
            'mysql:host=' . ($db['host'] ?? 'localhost') . ';dbname=' . ($db['name'] ?? '') . ';charset=utf8mb4',
            (string) ($db['user'] ?? ''),
            (string) ($db['password'] ?? ''),
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_TIMEOUT            => 5,     // connect timeout, seconds
                PDO::MYSQL_ATTR_FOUND_ROWS   => true,  // rowCount() counts matched rows, so "unchanged" isn't "missing"
            ]
        );
        $pdo->exec("SET time_zone = '" . date('P') . "'");  // NOW() in shop time
    }
    return $pdo;
}

/** Creates the tables if they don't exist yet; safe to run on every admin request. */
function db_ensure_schema(): void
{
    // valid_from / valid_until are the first and last day a coupon can be used (inclusive);
    // NULL means "from now on" and "no end date".
    db()->exec(sprintf(
        'CREATE TABLE IF NOT EXISTS coupons (
            id          INT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
            code        VARCHAR(32)      NOT NULL,
            percent     TINYINT UNSIGNED NOT NULL,
            valid_from  DATE             NULL,
            valid_until DATE             NULL,
            active      TINYINT(1)       NOT NULL DEFAULT 1,
            created_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_coupons_code (code),
            CONSTRAINT chk_coupons_percent CHECK (percent BETWEEN %d AND %d)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci',
        COUPON_MIN_PERCENT,
        COUPON_MAX_PERCENT
    ));
    db()->exec(
        'CREATE TABLE IF NOT EXISTS admin_login_attempts (
            ip_hash  CHAR(64)     NOT NULL PRIMARY KEY,
            failures INT UNSIGNED NOT NULL,
            first_at DATETIME     NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=ascii'
    );
    // One row per order sent through the site, for the admin stats. No customer data.
    // coupon_code/coupon_percent are snapshots, so history survives renaming or deleting a coupon.
    db()->exec(
        'CREATE TABLE IF NOT EXISTS orders (
            id             INT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
            created_at     DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
            package        VARCHAR(100)     NOT NULL,
            price          INT UNSIGNED     NOT NULL,
            coupon_id      INT UNSIGNED     NULL,
            coupon_code    VARCHAR(32)      NULL,
            coupon_percent TINYINT UNSIGNED NULL,
            discount       INT UNSIGNED     NOT NULL DEFAULT 0,
            total          INT UNSIGNED     NOT NULL,
            KEY idx_orders_created (created_at),
            CONSTRAINT fk_orders_coupon FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
    // For installs whose coupons table predates the start date.
    db_add_column_if_missing('coupons', 'valid_from', 'valid_from DATE NULL AFTER percent');
}

/** Adds a column to a table that was created before that column existed. */
function db_add_column_if_missing(string $table, string $column, string $definition): void
{
    $stmt = db()->prepare('SELECT COUNT(*) FROM information_schema.columns
                           WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?');
    $stmt->execute([$table, $column]);
    if ((int) $stmt->fetchColumn() === 0) {
        db()->exec("ALTER TABLE `$table` ADD COLUMN $definition");
    }
}

function db_is_duplicate(PDOException $e): bool
{
    return (int) ($e->errorInfo[1] ?? 0) === 1062;  // ER_DUP_ENTRY
}

/* ── Coupons ── */

function coupon_normalize(string $code): string
{
    return strtoupper(trim($code));
}

function coupon_code_is_valid(string $code): bool
{
    return preg_match('/^[A-Z0-9_-]{3,32}$/', $code) === 1;
}

/**
 * An active coupon as ['percent' => int, 'expired' => bool, 'not_started' => bool], or null.
 * The valid_from / valid_until days count as usable themselves (shop time). The column collation
 * is case-insensitive, so codes typed in lowercase in phpMyAdmin still match.
 */
function coupon_lookup(string $code): ?array
{
    $stmt = db()->prepare('SELECT percent,
                                  valid_until IS NOT NULL AND valid_until < CURDATE() AS expired,
                                  valid_from  IS NOT NULL AND valid_from  > CURDATE() AS not_started
                           FROM coupons WHERE code = ? AND active = 1 AND percent BETWEEN ? AND ?');
    $stmt->execute([$code, COUPON_MIN_PERCENT, COUPON_MAX_PERCENT]);
    $row = $stmt->fetch();
    return $row === false ? null : [
        'percent'     => (int) $row['percent'],
        'expired'     => (bool) $row['expired'],
        'not_started' => (bool) $row['not_started'],
    ];
}

/* ── JSON endpoints (api/) ── */

/** Headers shared by the api/ endpoints; anything but POST gets a 405. */
function api_start(): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Robots-Tag: noindex');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        json_response(405, ['error' => 'method_not_allowed']);
    }
}

function json_response(int $status, array $body): void
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
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
