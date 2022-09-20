<?php

namespace ImapOauth2\Exceptions;

use Illuminate\Auth\AuthenticationException;

class ImapOauth2CanException extends AuthenticationException
{
    /**
     * ImapOauth2 Callback Error
     *
     * @param string|null     $message  [description]
     * @param \Throwable|null $previous [description]
     * @param array           $headers  [description]
     * @param int|integer     $code     [description]
     */
    public function sss__construct(string $error = '')
    {

    }
}
