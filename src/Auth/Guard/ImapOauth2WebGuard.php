<?php

namespace ImapOauth2\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
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

        if($authen) {
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
       
        //dd($credentials);
        // Get Credentials
        if (!$credentials) {
            $credentials = ImapOauth2Web::retrieveToken();    
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
}
