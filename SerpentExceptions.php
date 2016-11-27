<?php

namespace k98kurz\Serpent;

class SerpentKeylengthException extends \InvalidArgumentException {}
class SerpentIVlengthException extends \InvalidArgumentException {}
class SerpentEncryptException extends \RuntimeException {}
class SerpentDecryptException extends \RuntimeException {}
