<?php

namespace PhalconApi\Auth\TokenParsers;

use PhalconApi\Auth\Session;
use PhalconApi\Constants\ErrorCodes;
use PhalconApi\Exception;

class JWTTokenParser implements \PhalconApi\Auth\TokenParserInterface
{
    const ALGORITHM_HS256 = 'HS256';
    const ALGORITHM_HS512 = 'HS512';
    const ALGORITHM_HS384 = 'HS384';
    const ALGORITHM_RS256 = 'RS256';

    protected $algorithm;
    protected $secret;


    public function __construct($secret, $algorithm = self::ALGORITHM_HS256)
    {
        $this->algorithm = $algorithm;
        $this->secret = $secret;
    }

    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;
    }


    public function getToken(Session $session, $expirationTime = null)
    {
        $tokenData = $this->create($session->getAccountTypeName(), $session->getIdentity(), $session->getStartTime(),
            $session->getExpirationTime());

        return $this->encode($tokenData);
    }

    protected function create($issuer, $user, $iat, $exp)
    {

        return [

            /*
            The iss (issuer) claim identifies the principal
            that issued the JWT. The processing of this claim
            is generally application specific.
            The iss value is a case-sensitive string containing
            a StringOrURI value. Use of this claim is OPTIONAL.
            ------------------------------------------------*/
            "iss" => $issuer,

            /*
            The sub (subject) claim identifies the principal
            that is the subject of the JWT. The Claims in a
            JWT are normally statements about the subject.
            The subject value MUST either be scoped to be
            locally unique in the context of the issuer or
            be globally unique. The processing of this claim
            is generally application specific. The sub value
            is a case-sensitive string containing a
            StringOrURI value. Use of this claim is OPTIONAL.
            ------------------------------------------------*/
            "sub" => $user,

            /*
            The iat (issued at) claim identifies the time at
            which the JWT was issued. This claim can be used
            to determine the age of the JWT. Its value MUST
            be a number containing a NumericDate value.
            Use of this claim is OPTIONAL.
            ------------------------------------------------*/
            "iat" => $iat,

            /*
            The exp (expiration time) claim identifies the
            expiration time on or after which the JWT MUST NOT
            be accepted for processing. The processing of the
            exp claim requires that the current date/time MUST
            be before the expiration date/time listed in the
            exp claim. Implementers MAY provide for some small
            leeway, usually no more than a few minutes,
            to account for clock skew. Its value MUST be a
            number containing a NumericDate value.
            Use of this claim is OPTIONAL.
            ------------------------------------------------*/
            "exp" => $exp,
        ];
    }

    public function encode($token)
    {
        $header = ['typ' => 'JWT', 'alg' => $this->algorithm];

        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($token));

        $signature = $this->sign("$headerEncoded.$payloadEncoded", $this->secret, $this->algorithm);
        $signatureEncoded = $this->base64UrlEncode($signature);

        return "$headerEncoded.$payloadEncoded.$signatureEncoded";
    }

    public function getSession($token)
    {
        $tokenData = $this->decode($token);

        return new Session($tokenData->iss, $tokenData->sub, $tokenData->iat, $tokenData->exp, $token);
    }

    public function decode($token)
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new Exception(ErrorCodes::AUTH_TOKEN_INVALID, 'Wrong number of segments');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $segments;

        $headerJson = $this->base64UrlDecode($headerEncoded);
        $payloadJson = $this->base64UrlDecode($payloadEncoded);
        $signature = $this->base64UrlDecode($signatureEncoded);

        $header = json_decode($headerJson);
        $payload = json_decode($payloadJson);

        if ($header === null || $payload === null) {
            throw new Exception(ErrorCodes::AUTH_TOKEN_INVALID, 'Invalid encoding');
        }

        if (empty($header->alg) || $header->alg !== $this->algorithm) {
            throw new Exception(ErrorCodes::AUTH_TOKEN_INVALID, 'Algorithm not supported');
        }

        if (!$this->verify("$headerEncoded.$payloadEncoded", $signature, $this->secret, $this->algorithm)) {
            throw new Exception(ErrorCodes::AUTH_TOKEN_INVALID, 'Signature verification failed');
        }

        return $payload;
    }

    protected function sign($msg, $key, $alg)
    {
        switch ($alg) {
            case self::ALGORITHM_HS256:
                return hash_hmac('sha256', $msg, $key, true);
            case self::ALGORITHM_HS384:
                return hash_hmac('sha384', $msg, $key, true);
            case self::ALGORITHM_HS512:
                return hash_hmac('sha512', $msg, $key, true);
            case self::ALGORITHM_RS256:
                $signature = '';
                $success = openssl_sign($msg, $signature, $key, OPENSSL_ALGO_SHA256);
                if (!$success) {
                    throw new Exception(ErrorCodes::GENERAL_SYSTEM, 'OpenSSL unable to sign data');
                }
                return $signature;
            default:
                throw new Exception(ErrorCodes::GENERAL_SYSTEM, 'Algorithm not supported');
        }
    }

    protected function verify($msg, $signature, $key, $alg)
    {
        switch ($alg) {
            case self::ALGORITHM_HS256:
                return hash_equals(hash_hmac('sha256', $msg, $key, true), $signature);
            case self::ALGORITHM_HS384:
                return hash_equals(hash_hmac('sha384', $msg, $key, true), $signature);
            case self::ALGORITHM_HS512:
                return hash_equals(hash_hmac('sha512', $msg, $key, true), $signature);
            case self::ALGORITHM_RS256:
                return openssl_verify($msg, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
            default:
                throw new Exception(ErrorCodes::GENERAL_SYSTEM, 'Algorithm not supported');
        }
    }

    protected function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
