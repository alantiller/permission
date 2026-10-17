<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** Invalid client configuration or an operation requiring disabled roles. */
class ConfigurationException extends BaseException
{
    protected const ERROR_CODE = 'configuration_error';
}
