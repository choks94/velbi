<?php
/*
 * Velbi admin — coupon codes (/admin/).
 * The password hash comes from includes/config.php (see includes/config.sample.php).
 */
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

const LOGIN_MAX_FAILURES   = 5;
const LOGIN_LOCK_SECONDS   = 900;   // 15 min
const SESSION_IDLE_SECONDS = 7200;  // 2 h

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
$configured = $hash !== '' && password_get_info($hash)['algoName'] !== 'unknown';
$loggedIn   = $configured && !empty($_SESSION['admin']);

function flash(string $type, string $text): void
{
    $_SESSION['flash'] = ['type' => $type, 'text' => $text];
}

/* ── Login throttling (per client IP) ── */

/**
 * Counts the attempt before the password is checked, so parallel requests
 * can't slip past the limit. Returns seconds left on the lock (0 = go ahead).
 */
function login_attempt_begin(string $key, int $now): int
{
    return store_update('login_attempts', function (array &$attempts) use ($key, $now): int {
        foreach ($attempts as $k => $entry) {
            if ($now - $entry['first'] >= LOGIN_LOCK_SECONDS) {
                unset($attempts[$k]);
            }
        }
        $entry = $attempts[$key] ?? ['count' => 0, 'first' => $now];
        if ($entry['count'] >= LOGIN_MAX_FAILURES) {
            return LOGIN_LOCK_SECONDS - ($now - $entry['first']);
        }
        $entry['count']++;
        $attempts[$key] = $entry;
        return 0;
    });
}

function login_attempts_clear(string $key): void
{
    store_update('login_attempts', function (array &$attempts) use ($key): void {
        unset($attempts[$key]);
    });
}

/* ── Actions ── */

function handle_login(string $hash): void
{
    $key  = 'ip:' . hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    $wait = login_attempt_begin($key, time());
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

function handle_create(): void
{
    $code    = coupon_normalize(post_string('code'));
    $percent = filter_var(post_string('percent'), FILTER_VALIDATE_INT, [
        'options' => ['min_range' => COUPON_MIN_PERCENT, 'max_range' => COUPON_MAX_PERCENT],
    ]);
    if (!coupon_code_is_valid($code)) {
        flash('error', 'Kod mora imati 3–32 znaka: slova A–Z, brojeve, crticu ili donju crtu.');
        return;
    }
    if ($percent === false) {
        flash('error', 'Popust mora biti ceo broj od ' . COUPON_MIN_PERCENT . ' do ' . COUPON_MAX_PERCENT . '.');
        return;
    }
    $added = store_update('coupons', function (array &$coupons) use ($code, $percent): bool {
        if (coupon_index($coupons, $code) !== null) {
            return false;
        }
        $coupons[] = ['code' => $code, 'percent' => $percent, 'active' => true, 'created_at' => date('c')];
        return true;
    });
    if ($added) {
        flash('ok', "Kupon $code (−$percent%) je dodat.");
    } else {
        flash('error', "Kupon $code već postoji.");
    }
}

function handle_set_active(): void
{
    $code   = coupon_normalize(post_string('code'));
    $active = post_string('active') === '1';
    $found  = store_update('coupons', function (array &$coupons) use ($code, $active): bool {
        $i = coupon_index($coupons, $code);
        if ($i === null) {
            return false;
        }
        $coupons[$i]['active'] = $active;
        return true;
    });
    if (!$found) {
        flash('error', 'Taj kupon više ne postoji.');
    } else {
        flash('ok', $active ? "Kupon $code je aktiviran." : "Kupon $code je deaktiviran — kupci ga više ne mogu koristiti.");
    }
}

function handle_delete(): void
{
    $code    = coupon_normalize(post_string('code'));
    $deleted = store_update('coupons', function (array &$coupons) use ($code): bool {
        $i = coupon_index($coupons, $code);
        if ($i === null) {
            return false;
        }
        array_splice($coupons, $i, 1);
        return true;
    });
    if ($deleted) {
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
    try {
        if (!hash_equals($_SESSION['csrf'], post_string('csrf'))) {
            flash('error', 'Sesija je istekla. Pokušajte ponovo.');
        } elseif (!$loggedIn) {
            if ($configured && post_string('action') === 'login') {
                handle_login($hash);
            }
        } else {
            switch (post_string('action')) {
                case 'create':     handle_create();     break;
                case 'set_active': handle_set_active(); break;
                case 'delete':     handle_delete();     break;
                case 'logout':     handle_logout();     break;
            }
        }
    } catch (Throwable $e) {
        error_log('[velbi] admin action failed: ' . $e->getMessage());
        flash('error', 'Došlo je do greške pri čuvanju. Pokušajte ponovo.');
    }
    header('Location: ' . $basePath, true, 303);
    exit;
}

/* ── Page ── */

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

$coupons   = [];
$loadError = false;
if ($loggedIn) {
    try {
        $coupons = array_reverse(store_read('coupons'));  // newest first
    } catch (Throwable $e) {
        error_log('[velbi] cannot load coupons: ' . $e->getMessage());
        $loadError = true;
    }
}
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
        input {
            width: 100%; font: inherit; color: #1F1209; background: #FAF6F1;
            border: 1px solid #E8D5C4; border-radius: 12px; padding: 11px 14px; outline: none;
        }
        input:focus { border-color: #C49A3C; box-shadow: 0 0 0 3px rgba(196,154,60,.18); }
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
        .btn-small:hover { border-color: #2C1A0E; }
        .btn-small.danger { color: #a5281b; }
        .btn-small.danger:hover { border-color: #a5281b; background: #fbeae8; }
        .link { font: inherit; font-size: 14px; font-weight: 600; color: #7a5c4a; background: none; border: none; cursor: pointer; padding: 6px 0; }
        .link:hover { color: #C49A3C; }

        .flash { border-radius: 12px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; font-weight: 500; }
        .flash-ok { background: #e8f5ea; color: #3f6445; border: 1px solid #cfe5d2; }
        .flash-error { background: #fbeae8; color: #a5281b; border: 1px solid #f1c9c4; }

        .login-form { display: grid; gap: 14px; margin-top: 18px; }
        .add-form { display: grid; grid-template-columns: 1fr 120px auto; gap: 12px; align-items: end; margin-top: 18px; }
        @media (max-width: 560px) {
            .add-form { grid-template-columns: 1fr 104px; }
            .add-form .btn { grid-column: 1 / -1; }
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
        .coupon-actions { display: flex; gap: 8px; }
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
            <p class="muted">Napravite fajl <code>includes/config.php</code> po uzoru na <code>includes/config.sample.php</code> i u njega upišite hash admin lozinke.</p>
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
            <h1>Kupon kodovi</h1>
            <p class="muted">Kupac unosi kod u formi za narudžbinu i cena paketa se odmah umanjuje za zadati procenat.</p>
            <form method="post" class="add-form">
                <?= $csrfField ?>
                <input type="hidden" name="action" value="create">
                <div>
                    <label for="code">Kod</label>
                    <input id="code" name="code" class="upper" required maxlength="32" pattern="[A-Za-z0-9_\-]{3,32}"
                           title="3–32 znaka: slova, brojevi, crtica ili donja crta" placeholder="npr. LETO20"
                           autocomplete="off" autocapitalize="characters" spellcheck="false">
                </div>
                <div>
                    <label for="percent">Popust (%)</label>
                    <input id="percent" name="percent" type="number" required inputmode="numeric"
                           min="<?= COUPON_MIN_PERCENT ?>" max="<?= COUPON_MAX_PERCENT ?>" step="1" placeholder="20">
                </div>
                <button type="submit" class="btn">Dodaj kupon</button>
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
                        $code    = (string) $coupon['code'];
                        $active  = (bool) $coupon['active'];
                        $created = strtotime((string) ($coupon['created_at'] ?? '')); ?>
                        <li class="coupon<?= $active ? '' : ' inactive' ?>">
                            <div>
                                <span class="coupon-code"><?= h($code) ?></span><span class="coupon-pct">−<?= (int) $coupon['percent'] ?>%</span>
                                <span class="badge <?= $active ? 'badge-on' : 'badge-off' ?>"><?= $active ? 'Aktivan' : 'Neaktivan' ?></span>
                                <?php if ($created): ?><div class="coupon-meta">Dodat <?= date('d.m.Y.', $created) ?></div><?php endif; ?>
                            </div>
                            <div class="coupon-actions">
                                <form method="post">
                                    <?= $csrfField ?>
                                    <input type="hidden" name="action" value="set_active">
                                    <input type="hidden" name="code" value="<?= h($code) ?>">
                                    <input type="hidden" name="active" value="<?= $active ? '0' : '1' ?>">
                                    <button type="submit" class="btn-small"><?= $active ? 'Deaktiviraj' : 'Aktiviraj' ?></button>
                                </form>
                                <form method="post" data-confirm="Obrisati kupon <?= h($code) ?>?">
                                    <?= $csrfField ?>
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="code" value="<?= h($code) ?>">
                                    <button type="submit" class="btn-small danger">Obriši</button>
                                </form>
                            </div>
                        </li>
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
</script>
</body>
</html>
