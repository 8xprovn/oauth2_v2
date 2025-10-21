<?php

namespace ImapOauth2\Auth;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use ImapOauth2\Models\ImapOauth2User;

class ImapOauth2WebUserProvider implements UserProvider
{
    /**
     * The user model.
     *
     * @var string
     */
    protected $model;

    /**
     * The Constructor
     *
     * @param string $model
     */

    public function __construct(ImapOauth2User $model)
    {
        $this->model = $model;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
       
        // if (
        //     !array_key_exists('phone', $credentials) || 
        //     !array_key_exists('contact_id', $credentials) 
        // ) {
        //     return null;
        // }

       
       // $credentials['user_id'] = $credentials['contact_id']; 

        return new ImapOauth2User($credentials);

        //    $class = '\\'.ltrim($this->model, '\\');
        //     return new $class($credentials);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */ 

     public function retrieveById($identifier)
    {
        if (!$identifier) {
            return null;
        }
        $user = \Microservices::Crm('Contacts')->detail($identifier);
        // $user = ($identifier == 1) ? ['is_superadmin' => true,'_id' => 1] : \Microservices::Hr('Employees')->detail($identifier);
        $class = $this->model;
        return new $class($user);
    }


    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }

    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false)
    {
        return false;
    }
}
