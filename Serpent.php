<?php
/**
 * Serpent encryption replacement for Crypt
 * @author k98kurz
 */

namespace k98kurz\Serpent;

class Serpent {
	/* a single instance to be used for stuff calls */
	public static $instance;

	/* keep the keys, iv, and mcrypt module in memory*/
	private static $key;
	private static $masterkey;
	private static $iv;
	private static $td;

	/* some config */
	private static $cipher = MCRYPT_SERPENT;
	private static $mode = MCRYPT_MODE_CFB;
	private static $keylength;
	private static $ivlength;

	/* some input/output stuff */
	private static $plaintextin;
	private static $ciphertextin;
	private static $plaintextout;
	private static $ciphertextout;

	/* constructor */
	public function __construct ()
	{
		// set the things
		self::$masterkey = env('APP_KEY');
		self::$key = self::$masterkey;
		self::$keylength = mcrypt_get_key_size(self::$cipher, self::$mode);
		self::$ivlength = mcrypt_get_iv_size(self::$cipher, self::$mode);
		self::$td = mcrypt_module_open(self::$cipher, '', self::$mode, '');
	}

	public static function init ($salt=null, $key=null)
	{
		// create a new instance if necessary
		if (!isset(self::$instance) || is_null(self::$instance))
			self::$instance = new self;
		// save any key passed in
		if (!is_null($key) && is_string($key))
			self::$key = $key;
		// save or generate an iv
		if (!is_null($salt) && is_string($salt)) {
			self::$iv = $salt;
		} else {
			self::$iv = openssl_random_pseudo_bytes(self::$ivlength);
		}
		// clear out input and output arrays
		self::$plaintextin = [];
		self::$ciphertextin = [];
		self::$plaintextout = [];
		self::$ciphertextout = [];

		// make sure the key makes sense
		$keylength = strlen(self::$key);
		if ($keylength !== self::$keylength) {
			// parse hexadecimal and base64, or throw an exception
			if ($keylength == self::$keylength * 2 && ctype_xdigit(self::$key))
				self::$key = hex2bin(self::$key);
			elseif (base64_decode(self::$key, true) && strlen(base64_decode(self::$key)) == self::$keylength)
				self::$key = base64_decode(self::$key);
			else
				throw new SerpentKeylengthException("Incorrect key length: $keylength < ".self::$keylength);
		}

		// make sure the iv makes sense
		$ivlength = strlen(self::$iv);
		if ($ivlength !== self::$ivlength) {
			// parse hexadecimal and base64, or throw an exception
			if ($ivlength == self::$ivlength * 2 && ctype_xdigit(self::$iv))
				self::$iv = hex2bin(self::$iv);
			elseif (base64_decode(self::$iv, true) && strlen(base64_decode(self::$iv)) == self::$ivlength)
				self::$iv = base64_decode(self::$iv);
			else
				throw new SerpentIVlengthException("Incorrect IV length: $ivlength < ".self::$ivlength);
		}

		// return instance for chaining
		return self::$instance;
	}

	// some magic
	public function __call ($name, $args)
	{
		switch ($name) {
			case 'encrypt':
				return call_user_func_array(array($this, 'encryptInstance'), $args);
				break;
			case 'decrypt':
				return call_user_func_array(array($this, 'decryptInstance'), $args);
				break;

			default:
				# code...
				break;
		}
	}
	public static function __callStatic ($name, $args)
	{
		switch ($name) {
			case 'encrypt':
				return call_user_func_array('static::encryptStatic', $args);
				break;
			case 'decrypt':
				return call_user_func_array('static::decryptStatic', $args);
				break;

			default:
				break;
		}
	}

	// simpler system: just return encrypted shit
	// returns "{iv};{ct}"
	public static function encryptStatic ($value=null, $key=null)
	{
		if (empty($value))
			return '';

		// do all the things
		self::init();
        if (!is_null($key))
            self::$key = $key;
		$ivl = self::$ivlength;
		if (strlen($value) < self::$ivlength) {
			$iv = openssl_random_pseudo_bytes(strlen($value));
			self::$iv = self::makeIV($iv);
		} else
            $iv = self::$iv;
		$ct = self::$instance->encrypt($value)->finalize()['ciphertext'][0];
		return base64_encode($iv) . ';' . $ct;
	}

	// simpler system: just return decrypted shit
	// takes "{iv};{ct}" and returns "{pt}"
	public static function decryptStatic ($value=null, $key=null)
	{
		if (empty($value))
			return '';
		$value = explode(';', $value);
		if (count($value) < 2)
			return '';

		// do all the things
		self::init();
        if (!is_null($key))
            self::$key = $key;
		if (ctype_xdigit($value[0]))
			$value[0] = hex2bin($value[0]);
		if (base64_decode($value[0], true))
			$value[0] = base64_decode($value[0]);
		if (strlen($value[0]) !== self::$ivlength)
			self::$iv = self::makeIV($value[0]);
		else
			self::$iv = $value[0];

		return self::$instance->decrypt($value[1])->finalize()['plaintext'][0];
	}

	public function encryptInstance ($value=null)
	{
		// pass if the input is empty
		if (is_null($value))
			return $this;

		// add to the plaintextin buffer
		if (is_string($value) || is_array($value))
			self::$plaintextin[] = $value;

		// return the instance for chaining
		return $this;
	}

	// adds to the buffer of things to decrypt
	public function decryptInstance ($value=null)
	{
		// pass if the input is empty
		if (is_null($value))
			return $this;

		// add to the ciphertextin buffer
		if (is_string($value) || is_array($value))
			self::$ciphertextin[] = $value;

		// return the instance for chaining
		return $this;
	}

	private function doEncrypt ($value)
	{
		// recursively handle arrays
		if (is_array($value)) {
			$ret = [];
			foreach ($value as $k => $v) {
				$ret[$k] = $this->doEncrypt($v);
			}

			return $ret;
		}

		if (is_string($value))
			return base64_encode(mcrypt_generic(self::$td, $value));
	}

	private function doDecrypt ($value)
	{
		// recursively handle arrays
		if (is_array($value)) {
			$ret = [];
			foreach ($value as $k => $v) {
				$ret[$k] = $this->doDecrypt($v);
			}

			return $ret;
		}

		if (!is_string($value))
			return '';
		if (base64_decode($value, true))
			$value = base64_decode($value);
		if (ctype_xdigit($value))
			$value = hex2bin($value);

		return mdecrypt_generic(self::$td, $value);
	}

	private function doEncryptHex ($value)
	{
		// recursively handle arrays
		if (is_array($value)) {
			$ret = [];
			foreach ($value as $k => $v) {
				$ret[$key] = $this->doDecryptHex($v);
			}

			return $ret;
		}

		if (!is_string($value))
			return '';

		return bin2hex(mcrypt_generic(self::$td, $value));
	}

	// run the encryption/decryption and return the result
	public function finalize ()
	{
		// initialize mcrypt
		mcrypt_generic_init(self::$td, self::$key, self::$iv);

		// encryption
		foreach (self::$plaintextin as $key => $value) {
			self::$ciphertextout[$key] = $this->doEncrypt($value);
		}

		// decryption
		foreach (self::$ciphertextin as $key => $value) {
			self::$plaintextout[$key] = $this->doDecrypt($value);
		}

		self::$instance = null;
		return [
			'ciphertext' => self::$ciphertextout,
			'plaintext' => self::$plaintextout,
			'iv' => base64_encode(self::$iv)
		];
	}

	// run the encryption/decryption and return result in hexadecimal
	public function finalizeHex ()
	{
		// initialize mcrypt
		mcrypt_generic_init(self::$td, self::$key, self::$iv);

		// encryption
		foreach (self::$plaintextin as $key => $value) {
			self::$ciphertextout[$key] = $this->doEncryptHex($value);
		}

		// decryption
		foreach (self::$ciphertextin as $key => $value) {
			self::$plaintextout[$key] = $this->doDecrypt($value);
		}

		self::$instance = null;
		return [
			'ciphertext' => self::$ciphertextout,
			'plaintext' => self::$plaintextout,
			'iv' => bin2hex(self::$iv)
		];
	}

	// make an iv (returns binary)
	public static function makeIV ($value='')
	{
		switch (self::$ivlength) {
			case 32:
				if (empty($value))
					return openssl_random_pseudo_bytes(32);
				return hash('sha256', $value, true);
			case 16:
				if (empty($value))
					return openssl_random_pseudo_bytes(16);
				return hash('haval128,5', $value, true);
			default:
				if (empty($value))
					return openssl_random_pseudo_bytes(self::$ivlength);
		}
	}

	// generate an hmac
	public static function hmac ($input, $key=null)
	{
		if (empty($input))
			return '';

		if (is_array($input)) {
			if (isset($input['iv']) && is_string($input['iv']))
				$iv = $input['iv'];
			else
				$iv = '';
			if (isset($input['ciphertext'])) {
				if (is_array($input['ciphertext']))
					$value = implode('', $input['ciphertext']);
				elseif (is_string($input['ciphertext']))
					$value = $input['ciphertext'];
			} elseif (isset($input['value']) && is_string($input['value']))
				$value = $input['value'];

			$value = $iv . $value;
		} else
			$value = is_string($input) ? $input : '';

		$key = (!empty($key) && is_string($key)) ? $key : self::$key;

		return base64_encode(hash_hmac('sha256', $value, $key, true));
	}

	// check an hmac
	public static function checkhmac ($hash, $input, $key=null)
	{
		if (empty($hash) || empty($input))
			return false;

		$key = (!empty($key) && is_string($key)) ? $key : self::$key;

		$expected = self::hmac($input, $key);
		$len = strlen($expected);
		if ($len !== strlen($hash))
			return false;

		$diff = 0;
		for ($i=0; $i<$len; ++$i) {
			$diff |= ord($expected[$i]) ^ ord($hash[$i]);
		}

		return $diff === 0;
	}

	// create a new encryption key
	public static function createKey ()
	{
		$t = new self;
		return base64_encode(openssl_random_pseudo_bytes(self::$keylength));
	}
}
