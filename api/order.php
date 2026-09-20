<?php
/*
 * POST /api/order.php  (package=…&price=2390&coupon=VELBI10)
 *   → {"ok": true}
 *
 * Called by the order form once the order email has gone out, so the admin
 * panel can show sales and coupon stats. Stores no customer data — only the
 * package, its price and the coupon. The discount is recomputed from the
 * coupon in the database rather than taken from the browser.
 */
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

// Far above any real order rate; caps how much junk a flood of fake requests could add to the stats.
const ORDERS_PER_HOUR_LIMIT = 200;

api_start();

$package = trim(post_string('package'));
$price   = filter_var(post_string('price'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]);
$code    = coupon_normalize(post_string('coupon'));
if (preg_match('/^.{1,100}$/u', $package) !== 1 || $price === false) {
    json_response(400, ['ok' => false]);
}

try {
    db_ensure_schema();  // orders can arrive before anyone has opened /admin/
    $pdo = db();
    if ((int) $pdo->query('SELECT COUNT(*) FROM orders WHERE created_at >= NOW() - INTERVAL 1 HOUR')->fetchColumn() >= ORDERS_PER_HOUR_LIMIT) {
        json_response(429, ['ok' => false]);
    }

    $coupon = null;
    if (coupon_code_is_valid($code)) {
        $stmt = $pdo->prepare('SELECT id, percent FROM coupons WHERE code = ?');
        $stmt->execute([$code]);
        $coupon = $stmt->fetch() ?: null;
    }
    $discount = $coupon === null ? 0 : (int) round($price * (int) $coupon['percent'] / 100);

    $pdo->prepare('INSERT INTO orders (package, price, coupon_id, coupon_code, coupon_percent, discount, total)
                   VALUES (?, ?, ?, ?, ?, ?, ?)')
        ->execute([
            $package,
            $price,
            $coupon === null ? null : (int) $coupon['id'],
            $coupon === null ? null : $code,
            $coupon === null ? null : (int) $coupon['percent'],
            $discount,
            $price - $discount,
        ]);
} catch (Throwable $e) {
    error_log('[velbi] order stats not recorded: ' . $e->getMessage());
    json_response(500, ['ok' => false]);
}

json_response(200, ['ok' => true]);
