<?php

namespace Console;

trait ArrayAccessTrait
{
    /**
     * @param $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        if (property_exists($this, $offset)) {
            return true;
        }

        return false;
    }

    /**
     * @param $offset
     *
     * @return mixed|null
     */
    public function offsetGet($offset)
    {
        return $this->offsetExists($offset) ? $this->{$offset} : null;
    }

    /**
     * @param $offset
     * @param $value
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        if ($this->offsetExists($offset)) {
            $this->{$offset} = $value;
        }
    }

    /**
     * @param $offset
     * @return void
     */
    public function offsetUnset($offset)
    {
        if ($this->offsetExists($offset)) {
            unset($this->{$offset});
        }
    }
}