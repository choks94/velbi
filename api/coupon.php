<?php
/*
 * POST /api/coupon.php  (code=VELBI10)
 *   → {"valid": true, "code": "VELBI10", "percent": 10}
 *   → {"valid": false, "reason": "expired"}      (active, but past its end date)
 *   → {"valid": false, "reason": "not_started"}  (active, but its start date hasn't come yet)
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
if ($coupon['expired'] || $coupon['not_started']) {
    json_response(200, ['valid' => false, 'reason' => $coupon['expired'] ? 'expired' : 'not_started']);
}
json_response(200, ['valid' => true, 'code' => $code, 'percent' => $coupon['percent']]);
