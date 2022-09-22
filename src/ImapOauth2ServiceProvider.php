<?php

namespace ImapOauth2;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
//use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use ImapOauth2\Auth\Guard\ImapOauth2WebGuard;
use ImapOauth2\Auth\ImapOauth2WebUserProvider;
use ImapOauth2\Middleware\ImapOauth2Authenticated;
use ImapOauth2\Middleware\ImapOauth2Can;
use ImapOauth2\Models\ImapOauth2User;
use ImapOauth2\Services\ImapOauth2Service;

class ImapOauth2ServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
      
        //$this->registerPolicies();
        // User Provider
        // $this->publishes([
        //     __DIR__.'/../config/imapoauth.php' => config_path('imapoauth.php'),
        // ]);
        Auth::provider('ImapOauth2-users', function($app, array $config) {
            //return new ImapOauth2WebUserProvider($config['model']);
            return new ImapOauth2WebUserProvider(new ImapOauth2User([]));
        });
    
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/Config/Config.php', 'imapoauth');
        
        // ImapOauth2 Web Guard
        Auth::extend('imap-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new ImapOauth2WebGuard($provider, $app->request);
        });

        // Facades
        $this->app->bind('imap-web', function($app) {
            return $app->make(ImapOauth2Service::class);
        });

        $this->app->bind('imap-guard', function($app) {
            return $app->make(ImapOauth2WebGuard::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('imap-web', [
            StartSession::class,
            ImapOauth2Authenticated::class,
        ]);

        $this->app['router']->aliasMiddleware('imap-web-can', ImapOauth2Can::class);

        // Interfaces
        $this->app->bind(ClientInterface::class, Client::class);
    }

    /**
     * Register the authentication routes for ImapOauth2.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $options = [
            'login' => env('ROUTE_PREFIX').'/login',
            'logout' => env('ROUTE_PREFIX').'/logout',
            'register' => env('ROUTE_PREFIX').'/register',
            'callback' => env('ROUTE_PREFIX').'/callback'
        ];
        // Register Routes
        $router = $this->app->make('router');
        
        if (! empty($options['login'])) {
            $router->get($options['login'], 'ImapOauth2\Controllers\AuthController@login')->name('ImapOauth2.login')->middleware('web');
        }

        if (! empty($options['logout'])) {
            $router->get($options['logout'], 'ImapOauth2\Controllers\AuthController@logout')->name('ImapOauth2.logout')->middleware('web');
        }
        if (! empty($options['register'])) {
            $router->get($options['register'], 'ImapOauth2\Controllers\AuthController@register')->name('ImapOauth2.register');
        }

        if (! empty($options['callback'])) {
            $router->get($options['callback'], 'ImapOauth2\Controllers\AuthController@callback')->name('ImapOauth2.callback')->middleware('web');
        }
    }

}
