<?php

namespace ImapOauth2\Middleware; 
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\URL;
use Illuminate\Http\Request;
use ImapOauth2\Facades\ImapOauth2Web;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;

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
            $this->queueSecureCookie($this->cookiePrefix . 'access_token', $accessToken, now()->addMinutes(60 * 24)); // 1 ngày

            if (!empty($refreshToken)) {
                $this->queueSecureCookie($this->cookiePrefix . 'refresh_token', $refreshToken, now()->addDays(6)); // ~6 ngày
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
     * Tạo cookie an toàn theo config session.
     */
    protected function queueSecureCookie(string $name, string $value, \DateTimeInterface $expiresAt): void
    {
        $path     = '/';
        $domain   = config('session.domain');
        $secure   = (bool) config('session.secure', request()->isSecure());
        $httpOnly = true; // NGĂN JS đọc token
        $sameSite = config('session.same_site', 'lax'); // 'lax'|'strict'|'none'

        // Laravel Cookie::queue mặc định đã mã hoá (EncryptCookies trong web middleware)
        Cookie::queue(
            Cookie::make($name, $value, 0, $path, $domain, $secure, $httpOnly, false, $sameSite)
                ->withExpires($expiresAt)
        );
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
