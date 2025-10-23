<?php

namespace ImapOauth2\Middleware;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\URL;
use Illuminate\Http\Request;
use ImapOauth2\Facades\ImapOauth2Web;  
class ImapOauth2Authenticated extends Authenticate
{
    protected string $cookiePrefix = 'imap_authen_user_';

    /**
     * Redirect user if it's not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function redirectTo($request)
    {
        /** @var Request $request */
        // 1) Ưu tiên lấy access_token từ header/bearer, sau đó mới tới query
        $accessTokenHeader = $request->header($this->cookiePrefix . 'access_token');
        $refreshTokenHeader = $request->header($this->cookiePrefix . 'refresh_token');

        $bearer = $request->bearerToken(); // Authorization: Bearer <token>

        $accessTokenQuery = $request->query($this->cookiePrefix . 'access_token');
        $refreshTokenQuery = $request->query($this->cookiePrefix . 'refresh_token');

        $accessToken = $accessTokenHeader ?: ($bearer ?: $accessTokenQuery);
        $refreshToken = $refreshTokenHeader ?: $refreshTokenQuery;

        // 2) Nếu có token → set cookie an toàn và redirect về URL sạch (không mang token)
        if (!empty($accessToken)) {
            Cookie::queue($this->cookiePrefix . 'access_token', $accessToken, 1440, null, null, true, false);

            if (!empty($refreshToken)) {
                Cookie::queue($this->cookiePrefix . 'refresh_token', $refreshToken, 8640, null, null, true, false);
            }

            // Xây URL sạch: loại bỏ các query chứa token
            $cleanUrl = $this->currentUrlWithout($request, [
                $this->cookiePrefix . 'access_token',
                $this->cookiePrefix . 'refresh_token',
            ]);

            return $cleanUrl;
        }

        // 3) Không có token → đẩy sang login, lưu state để quay lại
        $state = Session::getId();
        Session::put($state, $this->currentFullUrl($request)); // nhớ lại URL hiện tại (đầy đủ query hợp lệ)
        return ImapOauth2Web::getLoginUrl($state);
    }
 
    /**
     * Lấy URL hiện tại (full) – dùng URL::full(), fallback nếu cần.
     */
    protected function currentFullUrl(Request $request): string
    {
        return URL::full();
    }

    /**
     * Trả về URL hiện tại nhưng loại bỏ 1 số query keys (ví dụ access_token/refresh_token)
     */
    protected function currentUrlWithout(Request $request, array $removeKeys): string
    {
        $query = $request->query();
        foreach ($removeKeys as $k) {
            unset($query[$k]);
        }
        $base = URL::current();
        return $query ? $base . '?' . http_build_query($query) : $base;
    }
}
