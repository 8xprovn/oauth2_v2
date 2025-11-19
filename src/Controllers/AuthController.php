<?php

namespace ImapOauth2\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use ImapOauth2\Exceptions\ImapOauth2CallbackException;
use ImapOauth2\Facades\ImapOauth2Web;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $uri = $request->query('redirect_uri');
        if (!$uri) {
            $uri = env('APP_URL');
        }
        //////// RELOGIN ////////
        if (Auth::loginUsingAccessToken()) {
            return redirect($uri);
        }
        $state = base64_encode($uri);
        $url = KeycloakWeb::getLoginUrl($state);
        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {

        ImapOauth2Web::forgetToken();

        $url = ImapOauth2Web::getLogoutUrl();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logoutRedirect()
    {
        return redirect('/');
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = ImapOauth2Web::getRegisterUrl();
        return redirect($url);
    }

    /**
     * ImapOauth2 callback page
     *
     * @throws ImapOauth2CallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {

        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            return redirect('/');
        }

        $code = $request->input('code');
        $state = $request->input('state');

        $state = base64_decode($state);
        if (empty($state)) return redirect(route('ImapOauth2.logout'));
    
        if (!empty($code)) {
            $token = ImapOauth2Web::getAccessToken($code);
            if (Auth::loginUsingToken($token)) {
                return redirect($state);
            }
        }
        return redirect(route('ImapOauth2.logout'));
    }
}
