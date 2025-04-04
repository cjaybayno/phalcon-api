<?php

namespace PhalconApi;

class Exception extends \Exception
{
    protected ?string $developerInfo;
    protected null|array|object $userInfo;

    public function __construct($code, $message = "", $developerInfo = null, $userInfo = null)
    {
        parent::__construct($message ?? '', $code);

        $this->developerInfo = $developerInfo;
        $this->userInfo = $userInfo;
    }

    public function getDeveloperInfo()
    {
        return $this->developerInfo;
    }

    public function getUserInfo()
    {
        return $this->userInfo;
    }
}
