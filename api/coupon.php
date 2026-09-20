<?php
/*
 * POST /api/coupon.php  (code=VELBI10)
 *   → {"valid": true, "code": "VELBI10", "percent": 10}
 *   → {"valid": false, "reason": "expired"}  (active, but past its end date)
 *   → {"valid": false}
 *
 * Checks one code at a time, so the coupon list itself is never exposed.
 */
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

api_start();

$code = coupon_normalize(post_string('code'));
if (!coupon_code_is_valid($code)) {
    json_response(200, ['valid' => false]);
}

try {
    $coupon = coupon_lookup($code);
} catch (Throwable $e) {
    error_log('[velbi] coupon lookup failed: ' . $e->getMessage());
    json_response(500, ['valid' => false, 'error' => 'server_error']);
}

if ($coupon === null) {
    json_response(200, ['valid' => false]);
}
json_response(200, $coupon['expired']
    ? ['valid' => false, 'reason' => 'expired']
    : ['valid' => true, 'code' => $code, 'percent' => $coupon['percent']]);
