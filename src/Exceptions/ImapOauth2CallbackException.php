<?php

namespace ImapOauth2\Exceptions;

class ImapOauth2CallbackException extends \RuntimeException
{
    /**
     * ImapOauth2 Callback Error
     *
     * @param string|null     $message  [description]
     * @param \Throwable|null $previous [description]
     * @param array           $headers  [description]
     * @param int|integer     $code     [description]
     */
    public function __construct(string $error = '')
    {
        $message = '[ImapOauth2 Error] ' . $error;

        parent::__construct($message);
    }
}
