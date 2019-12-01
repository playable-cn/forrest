<?php

namespace Omniphx\Forrest\Formatters;

use Omniphx\Forrest\Interfaces\FormatterInterface;

class BaseFormatter implements FormatterInterface
{
    protected $mimeType = 'application/json';

    public function setHeaders()
    {
        $headers['Accept'] = $this->getDefaultMIMEType();
        $headers['Content-Type'] = $this->getDefaultMIMEType();

        return $headers;
    }

    public function setBody($data)
    {
        return json_encode($data);
    }

    public function formatResponse($response)
    {
        return json_decode($response->getBody(), true);
    }

    public function getDefaultMIMEType()
    {
        return $this->mimeType;
    }
}