<?php

namespace ImapOauth2\Middleware;

use Illuminate\Auth\Middleware\Authenticate;
use ImapOauth2\Facades\ImapOauth2Web;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\URL;

class ImapOauth2Authenticated extends Authenticate
{
    /**
     * Redirect user if it's not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function redirectTo($request)
    {
        //$preURL = URL::previous();
        $currentURL = URL::full();
        //$state =  bin2hex(openssl_random_pseudo_bytes(4));
        $state = Session::getId();
        Session::put($state,$currentURL);
        $url = ImapOauth2Web::getLoginUrl($state);
        return $url;
        //return redirect($url);
    }
}
