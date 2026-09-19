<?php
/*
 * POST /api/coupon.php  (code=VELBI10)
 *   → {"valid": true, "code": "VELBI10", "percent": 10}
 *   → {"valid": false}
 *
 * Checks one code at a time, so the coupon list itself is never exposed.
 */
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');

function respond(int $status, array $body): void
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, ['valid' => false, 'error' => 'method_not_allowed']);
}

$code = coupon_normalize(post_string('code'));
if (!coupon_code_is_valid($code)) {
    respond(200, ['valid' => false]);
}

try {
    $coupon = coupon_find_active($code);
} catch (Throwable $e) {
    error_log('[velbi] coupon lookup failed: ' . $e->getMessage());
    respond(500, ['valid' => false, 'error' => 'server_error']);
}

respond(200, $coupon === null
    ? ['valid' => false]
    : ['valid' => true, 'code' => $coupon['code'], 'percent' => $coupon['percent']]);
