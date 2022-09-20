<?php

namespace ImapOauth2\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use ImapOauth2\Exceptions\ImapOauth2CanException;
use ImapOauth2\Facades\ImapOauth2Web;

class ImapOauth2Can extends ImapOauth2Authenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        
    }
}
