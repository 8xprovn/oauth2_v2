<?php

namespace ImapOauth2\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Cookie;
use ImapOauth2\Exceptions\ImapOauth2CallbackException;
use ImapOauth2\Models\ImapOauth2User;
use ImapOauth2\Facades\ImapOauth2Web;
//use Illuminate\Contracts\Auth\UserProvider;
use ImapOauth2\Auth\ImapOauth2WebUserProvider as UserProvider;

class ImapOauth2WebGuard
{
    /**
     * @var null|Authenticatable|ImapOauth2User
     */
    protected $cookePrefix = "imap_authen_user_";
    protected $user;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $authen = $this->authenticate();

        if ($authen) {
            return $this->user;
        }

        return null;
        //return $this->user ?: $this->authenticate();
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->user_id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token'])) {
            return false;
        }
        /**
         * Store the section
         */

        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';

        ImapOauth2Web::saveToken($credentials);

        return $this->authenticate($credentials);
    }

    /**
     * Try to authenticate the user
     *
     * @throws ImapOauth2CallbackException
     * @return boolean
     */
    public function authenticate($credentials = array())
    {
        if (!$credentials) {
            $credentials = ImapOauth2Web::retrieveToken();
        }

        if (empty($credentials) && request()->hasHeader($this->cookePrefix . 'access_token')) {
            $credentials['access_token'] = request()->header($this->cookePrefix . 'access_token');
            Cookie::queue($this->cookePrefix . 'access_token', $credentials['access_token'], 1440, null, null, true, false);
        }
        if (empty($credentials) && request()->hasHeader($this->cookePrefix . 'refresh_token')) {
            $credentials['refresh_token'] = request()->header($this->cookePrefix . 'refresh_token');
            Cookie::queue($this->cookePrefix . 'refresh_token', $credentials['refresh_token'], 8640, null, null, true, false);
        }

        if (empty($credentials['access_token'])) {
            return false;
        }

        $user = ImapOauth2Web::getUserProfile($credentials);

        if (empty($user)) {
            ImapOauth2Web::forgetToken();
            return false;
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);

        $this->setUser($user);

        return true;
    }

    public function login(Authenticatable $user, $remember = false)
    {

        $this->setUser($user);
    }

    public function loginUsingToken($credentials)
    {
        if (empty($credentials['access_token'])) {
            return false;
        }
        $token = ImapOauth2Web::parseAccessToken($credentials['access_token']);
        if (!$token || empty($token['sub'])) {
            return false;
        }
        if (! is_null($user = $this->provider->retrieveById($token['sub']))) {
            $this->login($user);
            Cookie::queue($this->cookePrefix . 'access_token', $credentials['access_token'], 1440, null, null, true, false);
            Cookie::queue($this->cookePrefix . 'refresh_token', $credentials['refresh_token'], 8640, null, null, true, false);
            return $user;
        }
        return false;
    }
}
