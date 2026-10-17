<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** An assignment references a permission or role that has not been defined. */
class NotFoundException extends BaseException
{
    protected const ERROR_CODE = 'not_found';
}
