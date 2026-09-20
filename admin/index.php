<?php
/*
 * Velbi admin — coupon codes (/admin/).
 * Database and password settings come from includes/config.php (see includes/config.sample.php).
 */
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

const LOGIN_MAX_FAILURES   = 5;
const LOGIN_LOCK_SECONDS   = 900;   // 15 min
const SESSION_IDLE_SECONDS = 7200;  // 2 h

const STATS_PERIODS = [
    '7d'  => ['label' => '7 dana',  'days' => 7],
    '30d' => ['label' => '30 dana', 'days' => 30],
    'all' => ['label' => 'Ukupno',  'days' => null],
];

$nonce    = base64_encode(random_bytes(16));
$basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/admin/index.php')), '/') . '/';

header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
     . "font-src https://fonts.gstatic.com; script-src 'nonce-$nonce'; form-action 'self'; "
     . "frame-ancestors 'none'; base-uri 'none'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');

/* ── Session ── */
session_name('velbi_admin');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => $basePath,
    'secure'   => request_is_https(),
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

if (!empty($_SESSION['admin']) && time() - (int) ($_SESSION['seen'] ?? 0) > SESSION_IDLE_SECONDS) {
    $_SESSION = [];
    session_regenerate_id(true);
}
if (!empty($_SESSION['admin'])) {
    $_SESSION['seen'] = time();
}
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$hash       = admin_password_hash();
$configured = $hash !== '' && password_get_info($hash)['algoName'] !== 'unknown' && db_configured();
$loggedIn   = $configured && !empty($_SESSION['admin']);

$dbError = false;
if ($configured) {
    try {
        db_ensure_schema();
    } catch (Throwable $e) {
        error_log('[velbi] database unavailable: ' . $e->getMessage());
        $dbError = true;
    }
}

function flash(string $type, string $text): void
{
    $_SESSION['flash'] = ['type' => $type, 'text' => $text];
}

/* ── Login throttling (per client IP) ── */

/**
 * Counts the attempt before the password is checked, so parallel requests
 * can't slip past the limit. Returns seconds left on the lock (0 = go ahead).
 */
function login_attempt_begin(string $key): int
{
    $pdo = db();
    $pdo->exec(sprintf('DELETE FROM admin_login_attempts WHERE first_at <= NOW() - INTERVAL %d SECOND', LOGIN_LOCK_SECONDS));
    $pdo->prepare('INSERT INTO admin_login_attempts (ip_hash, failures, first_at) VALUES (?, 1, NOW())
                   ON DUPLICATE KEY UPDATE failures = failures + 1')->execute([$key]);
    $stmt = $pdo->prepare(sprintf(
        'SELECT failures, TIMESTAMPDIFF(SECOND, NOW(), first_at + INTERVAL %d SECOND) AS wait
         FROM admin_login_attempts WHERE ip_hash = ?',
        LOGIN_LOCK_SECONDS
    ));
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row !== false && (int) $row['failures'] > LOGIN_MAX_FAILURES ? max(1, (int) $row['wait']) : 0;
}

function login_attempts_clear(string $key): void
{
    db()->prepare('DELETE FROM admin_login_attempts WHERE ip_hash = ?')->execute([$key]);
}

/* ── Actions ── */

function handle_login(string $hash): void
{
    $key  = hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    $wait = login_attempt_begin($key);
    if ($wait > 0) {
        flash('error', 'Previše neuspešnih pokušaja. Pokušajte ponovo za ' . (int) ceil($wait / 60) . ' min.');
        return;
    }
    if (!password_verify(post_string('password'), $hash)) {
        flash('error', 'Pogrešna lozinka.');
        return;
    }
    login_attempts_clear($key);
    session_regenerate_id(true);
    $_SESSION['admin'] = true;
    $_SESSION['seen']  = time();
    $_SESSION['csrf']  = bin2hex(random_bytes(32));
}

/**
 * Validated [code, percent, valid_until] from the form — valid_until is 'Y-m-d', or null for
 * "bez roka" — or null after flashing what's wrong. A new coupon can't start out already expired.
 */
function coupon_form_input(bool $isNew): ?array
{
    $code    = coupon_normalize(post_string('code'));
    $percent = filter_var(post_string('percent'), FILTER_VALIDATE_INT, [
        'options' => ['min_range' => COUPON_MIN_PERCENT, 'max_range' => COUPON_MAX_PERCENT],
    ]);
    if (!coupon_code_is_valid($code)) {
        flash('error', 'Kod mora imati 3–32 znaka: slova A–Z, brojeve, crticu ili donju crtu.');
        return null;
    }
    if ($percent === false) {
        flash('error', 'Popust mora biti ceo broj od ' . COUPON_MIN_PERCENT . ' do ' . COUPON_MAX_PERCENT . '.');
        return null;
    }

    $validUntil = null;
    if (post_string('no_expiry') !== '1') {
        $validUntil = post_string('valid_until');
        $date       = DateTime::createFromFormat('!Y-m-d', $validUntil);
        if ($date === false || $date->format('Y-m-d') !== $validUntil || $validUntil < '2000-01-01' || $validUntil > '2099-12-31') {
            flash('error', 'Izaberite datum do kog kupon važi ili označite „bez roka“.');
            return null;
        }
        if ($isNew && $validUntil < date('Y-m-d')) {
            flash('error', 'Novi kupon ne može da važi do datuma koji je već prošao.');
            return null;
        }
    }
    return [$code, $percent, $validUntil];
}

/** "važi do 30.09.2026." or "bez roka važenja." for flash messages. */
function validity_text(?string $validUntil): string
{
    return $validUntil === null ? 'bez roka važenja.' : 'važi do ' . date_sr($validUntil);
}

function coupon_code_by_id(int $id): ?string
{
    $stmt = db()->prepare('SELECT code FROM coupons WHERE id = ?');
    $stmt->execute([$id]);
    $code = $stmt->fetchColumn();
    return $code === false ? null : (string) $code;
}

function handle_create(): void
{
    $input = coupon_form_input(true);
    if ($input === null) {
        return;
    }
    [$code, $percent, $validUntil] = $input;
    try {
        db()->prepare('INSERT INTO coupons (code, percent, valid_until) VALUES (?, ?, ?)')->execute([$code, $percent, $validUntil]);
    } catch (PDOException $e) {
        if (!db_is_duplicate($e)) {
            throw $e;
        }
        flash('error', "Kupon $code već postoji.");
        return;
    }
    flash('ok', "Kupon $code (−$percent%) je dodat — " . validity_text($validUntil));
}

/** Returns the query string to redirect to — back into edit mode when the input was rejected. */
function handle_update(): string
{
    $id    = (int) post_string('id');
    $input = coupon_form_input(false);
    if ($input === null) {
        return "?edit=$id";
    }
    [$code, $percent, $validUntil] = $input;
    try {
        $stmt = db()->prepare('UPDATE coupons SET code = ?, percent = ?, valid_until = ? WHERE id = ?');
        $stmt->execute([$code, $percent, $validUntil, $id]);
    } catch (PDOException $e) {
        if (!db_is_duplicate($e)) {
            throw $e;
        }
        flash('error', "Kupon $code već postoji.");
        return "?edit=$id";
    }
    if ($stmt->rowCount() === 0) {
        flash('error', 'Taj kupon više ne postoji.');
    } elseif ($validUntil !== null && $validUntil < date('Y-m-d')) {
        // Allowed on purpose (e.g. to end a promotion), but make sure it wasn't a typo.
        flash('ok', "Kupon $code je sačuvan, ali mu je rok važenja prošao (" . date_sr($validUntil) . ') — kupci ga više ne mogu koristiti.');
    } else {
        flash('ok', "Kupon $code (−$percent%) je sačuvan — " . validity_text($validUntil));
    }
    return '';
}

function handle_set_active(): void
{
    $id     = (int) post_string('id');
    $active = post_string('active') === '1';
    $code   = coupon_code_by_id($id);
    if ($code === null) {
        flash('error', 'Taj kupon više ne postoji.');
        return;
    }
    db()->prepare('UPDATE coupons SET active = ? WHERE id = ?')->execute([(int) $active, $id]);
    flash('ok', $active ? "Kupon $code je aktiviran." : "Kupon $code je deaktiviran — kupci ga više ne mogu koristiti.");
}

function handle_delete(): void
{
    $id   = (int) post_string('id');
    $code = coupon_code_by_id($id);
    if ($code !== null) {
        db()->prepare('DELETE FROM coupons WHERE id = ?')->execute([$id]);
        flash('ok', "Kupon $code je obrisan.");
    }
}

function handle_logout(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
    flash('ok', 'Odjavljeni ste.');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $redirect = '';
    try {
        if (!hash_equals($_SESSION['csrf'], post_string('csrf'))) {
            flash('error', 'Sesija je istekla. Pokušajte ponovo.');
        } elseif (!$loggedIn) {
            if ($configured && post_string('action') === 'login') {
                handle_login($hash);
            }
        } else {
            switch (post_string('action')) {
                case 'create':     handle_create();                 break;
                case 'update':     $redirect = handle_update();     break;
                case 'set_active': handle_set_active();             break;
                case 'delete':     handle_delete();                 break;
                case 'logout':     handle_logout();                 break;
            }
        }
    } catch (Throwable $e) {
        error_log('[velbi] admin action failed: ' . $e->getMessage());
        flash('error', 'Došlo je do greške. Pokušajte ponovo.');
    }
    header('Location: ' . $basePath . $redirect, true, 303);
    exit;
}

/* ── Stats ── */

function din(int $amount): string
{
    return number_format($amount, 0, ',', '.') . ' din';
}

function date_sr(string $datetime): string
{
    $ts = strtotime($datetime);
    return $ts === false ? '' : date('d.m.Y.', $ts);
}

/** Stat-tile amount: 56.340, or 1,2 mil. past a million so it fits the tile. */
function tile_amount(int $amount): string
{
    return $amount >= 1000000
        ? number_format($amount / 1000000, 1, ',', '.') . ' mil.'
        : number_format($amount, 0, ',', '.');
}

/** Totals plus package and coupon breakdowns of the orders since $since (null = all time). */
function sales_stats(?string $since): array
{
    $where  = $since === null ? '1 = 1' : 'created_at >= ?';
    $params = $since === null ? [] : [$since];
    $rows   = function (string $sql) use ($params): array {
        $stmt = db()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    };
    $totals = $rows("SELECT COUNT(*) AS orders, COALESCE(SUM(total), 0) AS revenue, COALESCE(SUM(discount), 0) AS discount,
                            COALESCE(SUM(coupon_code IS NOT NULL), 0) AS coupon_orders
                     FROM orders WHERE $where")[0];
    return array_map('intval', $totals) + [
        'packages' => $rows("SELECT package AS label, COUNT(*) AS orders
                             FROM orders WHERE $where GROUP BY package ORDER BY orders DESC, package"),
        'coupons'  => $rows("SELECT coupon_code AS label, COUNT(*) AS orders, SUM(discount) AS discount
                             FROM orders WHERE $where AND coupon_code IS NOT NULL
                             GROUP BY coupon_code ORDER BY orders DESC, coupon_code"),
    ];
}

/** Keeps a breakdown short: past $max rows, the tail folds into one "Ostali" row. */
function fold_rows(array $rows, int $max): array
{
    if (count($rows) <= $max) {
        return $rows;
    }
    $rest = ['label' => 'Ostali'];
    foreach (array_slice($rows, $max - 1) as $row) {
        foreach ($row as $key => $value) {
            if ($key !== 'label') {
                $rest[$key] = ($rest[$key] ?? 0) + (int) $value;
            }
        }
    }
    return array_merge(array_slice($rows, 0, $max - 1), [$rest]);
}

/** Horizontal bars, each the row's share of all $total orders; $detail formats the text beside it. */
function share_bars(array $rows, int $total, callable $detail): string
{
    $html = '';
    foreach (fold_rows($rows, 5) as $row) {
        $share = $total > 0 ? (int) $row['orders'] / $total * 100 : 0;
        $html .= '<li><div class="bar-head"><span>' . h((string) $row['label']) . '</span>'
               . '<span class="bar-value">' . h($detail($row, (int) round($share))) . '</span></div>'
               . '<div class="bar-track"><div class="bar-fill" style="width:' . round($share, 1) . '%"></div></div></li>';
    }
    return '<ul class="bars">' . $html . '</ul>';
}

/**
 * Code, percent and valid-until fields shared by the add and edit forms. $coupon holds the current
 * values ([] for a new coupon); $prefix keeps element ids unique when both forms are on the page.
 */
function coupon_fields(string $prefix, array $coupon): string
{
    $isNew    = $coupon === [];
    $noExpiry = !$isNew && $coupon['valid_until'] === null;
    ob_start(); ?>
    <div>
        <label for="<?= $prefix ?>code">Kod</label>
        <input id="<?= $prefix ?>code" name="code" class="upper" value="<?= h((string) ($coupon['code'] ?? '')) ?>" required maxlength="32"
               pattern="[A-Za-z0-9_\-]{3,32}" title="3–32 znaka: slova, brojevi, crtica ili donja crta" placeholder="npr. LETO20"
               autocomplete="off" autocapitalize="characters" spellcheck="false"<?= $isNew ? '' : ' autofocus' ?>>
    </div>
    <div>
        <label for="<?= $prefix ?>percent">Popust (%)</label>
        <input id="<?= $prefix ?>percent" name="percent" type="number" value="<?= h((string) ($coupon['percent'] ?? '')) ?>" required
               inputmode="numeric" min="<?= COUPON_MIN_PERCENT ?>" max="<?= COUPON_MAX_PERCENT ?>" step="1" placeholder="20">
    </div>
    <div class="field-date">
        <div class="label-row">
            <label for="<?= $prefix ?>valid_until">Važi do</label>
            <label class="check"><input type="checkbox" name="no_expiry" value="1" data-toggles="<?= $prefix ?>valid_until"<?= $noExpiry ? ' checked' : '' ?>> bez roka</label>
        </div>
        <input id="<?= $prefix ?>valid_until" name="valid_until" type="date" value="<?= h((string) ($coupon['valid_until'] ?? '')) ?>"
               <?= $isNew ? 'min="' . date('Y-m-d') . '" ' : '' ?>max="2099-12-31">
    </div>
    <?php
    return (string) ob_get_clean();
}

/* ── Page ── */

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

$period = is_string($_GET['period'] ?? null) && array_key_exists($_GET['period'], STATS_PERIODS) ? $_GET['period'] : '30d';
$days   = STATS_PERIODS[$period]['days'];

$coupons   = [];
$stats     = null;
$loadError = false;
if ($loggedIn && !$dbError) {
    try {
        // Usage per coupon is lifetime and follows the coupon through renames (joined by id).
        $coupons = db()->query(
            'SELECT c.id, c.code, c.percent, c.valid_until, c.active, c.created_at,
                    c.valid_until IS NOT NULL AND c.valid_until < CURDATE() AS expired,
                    COUNT(o.id) AS uses, COALESCE(SUM(o.discount), 0) AS discount,
                    COALESCE(SUM(o.total), 0) AS revenue, MAX(o.created_at) AS last_used
             FROM coupons c LEFT JOIN orders o ON o.coupon_id = c.id
             GROUP BY c.id, c.code, c.percent, c.valid_until, c.active, c.created_at
             ORDER BY c.id DESC'
        )->fetchAll();
        $stats = sales_stats($days === null ? null : date('Y-m-d 00:00:00', strtotime('-' . ($days - 1) . ' days')));
    } catch (Throwable $e) {
        error_log('[velbi] cannot load coupons/stats: ' . $e->getMessage());
        $loadError = true;
    }
}
$editId    = (int) (is_string($_GET['edit'] ?? null) ? $_GET['edit'] : 0);
$csrfField = '<input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">';
?>
<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Velbi admin · Kupon kodovi</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; }
        body {
            font-family: 'DM Sans', system-ui, sans-serif;
            font-size: 16px;
            line-height: 1.6;
            color: #1F1209;
            background: #FAF6F1;
            -webkit-font-smoothing: antialiased;
        }
        main { max-width: 760px; margin: 0 auto; padding: 20px 16px 64px; }
        h1, h2 { font-family: 'Playfair Display', serif; color: #2C1A0E; line-height: 1.2; }
        h1 { font-size: 26px; margin-bottom: 6px; }
        h2 { font-size: 20px; margin-bottom: 14px; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; background: #F0E8DF; padding: 1px 6px; border-radius: 6px; }

        header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 24px; }
        .logo { font-family: 'Playfair Display', serif; font-weight: 700; font-size: 24px; color: #2C1A0E; text-decoration: none; }
        .logo small {
            font-family: 'DM Sans', sans-serif; font-size: 11px; font-weight: 700;
            letter-spacing: .2em; text-transform: uppercase; color: #C49A3C; margin-left: 8px;
        }

        .card {
            background: #FFF9F4; border: 1px solid #E8D5C4; border-radius: 20px;
            padding: 24px; margin-bottom: 20px; box-shadow: 0 4px 24px rgba(44,26,14,.08);
        }
        .card.narrow { max-width: 400px; margin: 48px auto; }
        .muted { color: #7a5c4a; font-size: 14px; }

        label { display: block; font-size: 14px; font-weight: 600; color: #2C1A0E; margin-bottom: 4px; }
        input:not([type="checkbox"]) {
            width: 100%; font: inherit; color: #1F1209; background: #FAF6F1;
            border: 1px solid #E8D5C4; border-radius: 12px; padding: 11px 14px; outline: none;
        }
        input:not([type="checkbox"]):focus { border-color: #C49A3C; box-shadow: 0 0 0 3px rgba(196,154,60,.18); }
        input:disabled { opacity: .45; cursor: not-allowed; }
        .upper { text-transform: uppercase; }
        .upper::placeholder { text-transform: none; }

        .btn {
            font: inherit; font-weight: 600; color: #fff; background: #C49A3C;
            border: none; border-radius: 12px; padding: 12px 22px; cursor: pointer; transition: background-color .2s;
        }
        .btn:hover { background: #9e5518; }
        .btn-small {
            font: inherit; font-size: 13px; font-weight: 600; color: #2C1A0E; background: transparent;
            border: 1px solid #E8D5C4; border-radius: 10px; padding: 6px 14px; cursor: pointer; transition: border-color .2s, background-color .2s;
        }
        a.btn-small { display: inline-block; text-align: center; text-decoration: none; }
        .btn-small:hover { border-color: #2C1A0E; }
        .btn-small.danger { color: #a5281b; }
        .btn-small.danger:hover { border-color: #a5281b; background: #fbeae8; }
        .link { font: inherit; font-size: 14px; font-weight: 600; color: #7a5c4a; background: none; border: none; cursor: pointer; padding: 6px 0; }
        .link:hover { color: #C49A3C; }

        .flash { border-radius: 12px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; font-weight: 500; }
        .flash-ok { background: #e8f5ea; color: #3f6445; border: 1px solid #cfe5d2; }
        .flash-error { background: #fbeae8; color: #a5281b; border: 1px solid #f1c9c4; }

        .login-form { display: grid; gap: 14px; margin-top: 18px; }
        /* Add and edit forms: code · percent · valid until · buttons; two columns on narrow screens. */
        .coupon-form { display: grid; grid-template-columns: 1fr 104px 180px auto; gap: 12px; align-items: end; width: 100%; margin-top: 18px; }
        .coupon .coupon-form { margin-top: 0; }
        .form-actions { display: flex; gap: 8px; }
        .form-actions .btn-small { padding: 11px 16px; }
        .label-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
        .check { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 500; color: #7a5c4a; cursor: pointer; }
        .check input { margin: 0; accent-color: #A87C2A; }
        @media (max-width: 760px) {
            .coupon-form { grid-template-columns: 1fr 104px; }
            .field-date, .form-actions { grid-column: 1 / -1; }
            .form-actions .btn { flex: 1; }
        }

        .coupons { list-style: none; padding: 0; }
        .coupon {
            display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
            gap: 10px 16px; padding: 14px 0; border-top: 1px solid #F0E8DF;
        }
        .coupon:first-child { border-top: none; padding-top: 0; }
        .coupon-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 600; font-size: 16px; letter-spacing: .04em; color: #2C1A0E; }
        .coupon-pct { font-weight: 700; color: #C49A3C; margin-left: 8px; }
        .coupon-meta { font-size: 12px; color: #9a7a6a; }
        .coupon.inactive .coupon-code, .coupon.inactive .coupon-pct { opacity: .45; }
        .badge {
            display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
            padding: 2px 8px; border-radius: 20px; margin-left: 8px; vertical-align: 2px;
        }
        .badge-on { background: #e8f5ea; color: #3f6445; }
        .badge-off { background: #F0E8DF; color: #7a5c4a; }
        .badge-expired { background: #fbeae8; color: #a5281b; }
        /* Long details wrap inside the text column; the buttons only drop below it on narrow screens. */
        .coupon-info { flex: 1 1 260px; min-width: 0; }
        .coupon-actions { display: flex; gap: 8px; }
        .coupon-meta strong { color: #2C1A0E; }

        /* ── Stats ── */
        h3 { font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #7a5c4a; margin-bottom: 10px; }
        .stats-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px 16px; margin-bottom: 18px; }
        .stats-head h1 { margin-bottom: 0; }
        .tabs { display: inline-flex; gap: 2px; padding: 3px; background: #F0E8DF; border-radius: 10px; }
        .tab { font-size: 13px; font-weight: 600; color: #7a5c4a; text-decoration: none; padding: 5px 12px; border-radius: 8px; }
        .tab:hover { color: #2C1A0E; }
        .tab.active { background: #FFF9F4; color: #2C1A0E; box-shadow: 0 1px 3px rgba(44,26,14,.12); }
        /* Sales tiles on the first row, the two coupon tiles on the second. */
        .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; }
        .kpi { grid-column: span 2; background: #FAF6F1; border: 1px solid #F0E8DF; border-radius: 14px; padding: 12px 14px; }
        .kpi-coupon { grid-column: span 3; }
        @media (max-width: 560px) {
            .kpis { grid-template-columns: 1fr 1fr; }
            .kpi, .kpi-coupon { grid-column: span 1; }
            .kpi-avg { grid-column: 1 / -1; }
        }
        .kpi-label { font-size: 12px; font-weight: 600; color: #7a5c4a; }
        .kpi-value { font-size: 22px; font-weight: 600; color: #2C1A0E; line-height: 1.3; }
        .kpi-value small { font-size: 13px; font-weight: 500; color: #7a5c4a; }
        .kpi-sub { font-size: 12px; color: #9a7a6a; }
        .breakdowns { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px 32px; margin-top: 22px; }
        .bars { list-style: none; padding: 0; display: grid; gap: 10px; }
        .bar-head { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; color: #2C1A0E; }
        .bar-value { color: #7a5c4a; white-space: nowrap; font-variant-numeric: tabular-nums; }
        /* Single series: one hue (a darker step of the brand caramel that clears 3:1 on the card). */
        .bar-track { height: 8px; margin-top: 4px; background: #F0E8DF; border-radius: 0 4px 4px 0; }
        .bar-fill { height: 100%; min-width: 2px; background: #A87C2A; border-radius: 0 4px 4px 0; }
        .stats-note { font-size: 12px; color: #9a7a6a; margin-top: 18px; }
    </style>
</head>
<body>
<main>
    <header>
        <span class="logo">Velbi.<small>Admin</small></span>
        <?php if ($loggedIn): ?>
            <form method="post">
                <?= $csrfField ?>
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="link">Odjavi se</button>
            </form>
        <?php endif; ?>
    </header>

    <?php if ($flash): ?>
        <div class="flash <?= $flash['type'] === 'ok' ? 'flash-ok' : 'flash-error' ?>" role="status"><?= h((string) $flash['text']) ?></div>
    <?php endif; ?>

    <?php if (!$configured): ?>
        <section class="card">
            <h1>Admin nije podešen</h1>
            <p class="muted">Napravite fajl <code>includes/config.php</code> po uzoru na <code>includes/config.sample.php</code> i u njega upišite podatke o bazi i hash admin lozinke.</p>
        </section>

    <?php elseif ($dbError): ?>
        <section class="card">
            <h1>Baza nije dostupna</h1>
            <p class="muted">Ne mogu da se povežem sa bazom podataka. Proverite podatke o bazi u <code>includes/config.php</code> (hPanel → Baze podataka).</p>
        </section>

    <?php elseif (!$loggedIn): ?>
        <section class="card narrow">
            <h1>Prijava</h1>
            <form method="post" class="login-form">
                <?= $csrfField ?>
                <input type="hidden" name="action" value="login">
                <div>
                    <label for="password">Lozinka</label>
                    <input type="password" id="password" name="password" required autofocus autocomplete="current-password">
                </div>
                <button type="submit" class="btn">Prijavi se</button>
            </form>
        </section>

    <?php else: ?>
        <section class="card">
            <div class="stats-head">
                <h1>Pregled prodaje</h1>
                <nav class="tabs" aria-label="Period">
                    <?php foreach (STATS_PERIODS as $key => $option): ?>
                        <a href="?period=<?= $key ?>" class="tab<?= $key === $period ? ' active' : '' ?>"<?= $key === $period ? ' aria-current="page"' : '' ?>><?= $option['label'] ?></a>
                    <?php endforeach; ?>
                </nav>
            </div>
            <?php if ($loadError): ?>
                <p class="flash flash-error">Statistika trenutno ne može da se učita. Osvežite stranicu.</p>
            <?php elseif ($stats['orders'] === 0): ?>
                <p class="muted"><?= $days === null
                    ? 'Još nema narudžbina. Od sada se ovde računa svaka narudžbina poslata preko sajta.'
                    : 'Nema narudžbina u ovom periodu.' ?></p>
            <?php else: ?>
                <div class="kpis">
                    <div class="kpi">
                        <div class="kpi-label">Narudžbine</div>
                        <div class="kpi-value"><?= $stats['orders'] ?></div>
                    </div>
                    <div class="kpi">
                        <div class="kpi-label">Prihod</div>
                        <div class="kpi-value"><?= tile_amount($stats['revenue']) ?><small> din</small></div>
                        <div class="kpi-sub">bez dostave</div>
                    </div>
                    <div class="kpi kpi-avg">
                        <div class="kpi-label">Prosečna narudžbina</div>
                        <div class="kpi-value"><?= tile_amount((int) round($stats['revenue'] / $stats['orders'])) ?><small> din</small></div>
                    </div>
                    <div class="kpi kpi-coupon">
                        <div class="kpi-label">Sa kuponom</div>
                        <div class="kpi-value"><?= $stats['coupon_orders'] ?></div>
                        <div class="kpi-sub"><?= (int) round($stats['coupon_orders'] / $stats['orders'] * 100) ?>% narudžbina</div>
                    </div>
                    <div class="kpi kpi-coupon">
                        <div class="kpi-label">Odobren popust</div>
                        <div class="kpi-value"><?= tile_amount($stats['discount']) ?><small> din</small></div>
                    </div>
                </div>
                <div class="breakdowns">
                    <div>
                        <h3>Paketi</h3>
                        <?= share_bars($stats['packages'], $stats['orders'], function (array $row, int $share): string {
                            return $row['orders'] . ' · ' . $share . '%';
                        }) ?>
                    </div>
                    <div>
                        <h3>Kuponi</h3>
                        <?php if ($stats['coupons']): ?>
                            <?= share_bars($stats['coupons'], $stats['orders'], function (array $row, int $share): string {
                                return $row['orders'] . ' · ' . $share . '% · popust ' . din((int) $row['discount']);
                            }) ?>
                        <?php else: ?>
                            <p class="muted">Nijedna narudžbina sa kuponom u ovom periodu.</p>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
            <p class="stats-note">Računaju se narudžbine poslate preko sajta, bez podataka o kupcima. Iznosi su bez dostave, a otkazane narudžbine se ne oduzimaju.</p>
        </section>

        <section class="card">
            <h2>Kupon kodovi</h2>
            <p class="muted">Kupac unosi kod u formi za narudžbinu i cena paketa se odmah umanjuje za zadati procenat. Kupon važi zaključno sa izabranim datumom.</p>
            <form method="post" class="coupon-form">
                <?= $csrfField ?>
                <input type="hidden" name="action" value="create">
                <?= coupon_fields('', []) ?>
                <div class="form-actions">
                    <button type="submit" class="btn">Dodaj kupon</button>
                </div>
            </form>
        </section>

        <section class="card">
            <h2>Svi kuponi <span class="muted">(<?= count($coupons) ?>)</span></h2>
            <?php if ($loadError): ?>
                <p class="flash flash-error">Kuponi trenutno ne mogu da se učitaju. Osvežite stranicu.</p>
            <?php elseif (!$coupons): ?>
                <p class="muted">Još nema kupona. Dodajte prvi iznad.</p>
            <?php else: ?>
                <ul class="coupons">
                    <?php foreach ($coupons as $coupon):
                        $id      = (int) $coupon['id'];
                        $code    = (string) $coupon['code'];
                        $percent = (int) $coupon['percent'];
                        $active  = (bool) $coupon['active'];
                        $expired = (bool) $coupon['expired'];
                        $uses    = (int) $coupon['uses'];
                        // A switched-off coupon reads "Neaktivan" even if it has also expired.
                        [$status, $badge] = !$active ? ['Neaktivan', 'badge-off'] : ($expired ? ['Istekao', 'badge-expired'] : ['Aktivan', 'badge-on']); ?>
                        <?php if ($id === $editId): ?>
                            <li class="coupon">
                                <form method="post" class="coupon-form">
                                    <?= $csrfField ?>
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="id" value="<?= $id ?>">
                                    <?= coupon_fields('edit-', $coupon) ?>
                                    <div class="form-actions">
                                        <button type="submit" class="btn">Sačuvaj</button>
                                        <a href="./" class="btn-small">Otkaži</a>
                                    </div>
                                </form>
                            </li>
                        <?php else: ?>
                            <li class="coupon<?= $status === 'Aktivan' ? '' : ' inactive' ?>">
                                <div class="coupon-info">
                                    <span class="coupon-code"><?= h($code) ?></span><span class="coupon-pct">−<?= $percent ?>%</span>
                                    <span class="badge <?= $badge ?>"><?= $status ?></span>
                                    <div class="coupon-meta">
                                        <?= $coupon['valid_until'] === null ? 'Bez roka važenja' : ($expired ? 'Važio do ' : 'Važi do ') . date_sr((string) $coupon['valid_until']) ?>
                                        · dodat <?= date_sr((string) $coupon['created_at']) ?><br>
                                        <?php if ($uses > 0): ?>
                                            Korišćenja: <strong><?= $uses ?></strong> · popust <?= din((int) $coupon['discount']) ?> · prihod <?= din((int) $coupon['revenue']) ?>
                                            · poslednji put <?= date_sr((string) $coupon['last_used']) ?>
                                        <?php else: ?>
                                            Još nije korišćen
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="coupon-actions">
                                    <a href="?edit=<?= $id ?>" class="btn-small">Izmeni</a>
                                    <form method="post">
                                        <?= $csrfField ?>
                                        <input type="hidden" name="action" value="set_active">
                                        <input type="hidden" name="id" value="<?= $id ?>">
                                        <input type="hidden" name="active" value="<?= $active ? '0' : '1' ?>">
                                        <button type="submit" class="btn-small"><?= $active ? 'Deaktiviraj' : 'Aktiviraj' ?></button>
                                    </form>
                                    <form method="post" data-confirm="Obrisati kupon <?= h($code) ?>?">
                                        <?= $csrfField ?>
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="id" value="<?= $id ?>">
                                        <button type="submit" class="btn-small danger">Obriši</button>
                                    </form>
                                </div>
                            </li>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </section>
    <?php endif; ?>
</main>
<script nonce="<?= h($nonce) ?>">
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!confirm(form.dataset.confirm)) e.preventDefault();
        });
    });
    // "bez roka" switches the date off; without it a date is required.
    document.querySelectorAll('input[data-toggles]').forEach(function (box) {
        var date = document.getElementById(box.dataset.toggles);
        function sync() {
            date.disabled = box.checked;
            date.required = !box.checked;
        }
        box.addEventListener('change', function () {
            sync();
            if (!box.checked) date.focus();
        });
        sync();
    });
</script>
</body>
</html>
