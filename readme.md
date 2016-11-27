# [Serpent Encryption Library](https://github.com/k98kurz/serpent)

This is essentially a small crypto library that I wrote to avoid dependency issues when making several servers talk to each other. As such, it requires only the php-mcrypt mod.

## Dependency

Since I wanted this to be as portable as possible, I decided to keep only the bare minimum dependency: the php-mcrypt extension.

## Usage

If you use an autoloader, just put the following at the beginning of the file in which you want to use it:

	use k98kurz\Serpent as Serpent;

If not using an autoloader, `require_once` both files before the `use` statement.

Note that you should have a default encryption key stored in the `APP_KEY` environment variable. If not, you will need to manually specify a key.

### Note About Ciphertext Encoding

Encrypted data is returned in base64 by default. It can optionally output hex.

### Encrypt/Decrypt a String

	$plaintext = 'Hello World';
	$ciphertext = Serpent::encrypt($plaintext);
	// returns "$iv;$ciphertext"
	$decrypted = Serpent::decrypt($ciphertext);
	// returns "Hello World"

### Encrypt/Decrypt an Array

	$plaintext = ['Hello', 'World'];
	$ciphertext = Serpent::encrypt($plaintext);
	// returns ['ciphertext' => [string, string], 'iv' => string]
	$decrypted = Serpent::decrypt($ciphertext);
	// return ['Hello', 'World']

### Encrypt Keys of Associative Arrays

	Serpent::setArrayOption(true);
	// blah blah

### More Control

To manually specify multiple things to process in one mcrypt instance, chain things like jQuery:

	$result = Serpent::init()->encrypt('hello')->encrypt(['my', 'world'])->finalize();
	// returns ['ciphertext' => [string, [string, string], 'plaintext' => [], 'iv' => string]
	$ciphertext = $result['ciphertext'];
	$iv = $result['iv'];
	$result = Serpent::init($iv)->decrypt($ciphertext[0])->decrypt($ciphertext[1])->finalize();
	// returns ['ciphertext' => [], 'plaintext'=> ['hello', ['my', 'world']], 'iv' => string]

### Utility Methods

Because they are sometimes necessary, I have included 4 utility methods:

	$iv = Serpent::makeIV(); // generate new iv
	$iv = Serpent::makeIV($seed); // generate an iv by hashing a seed
	$hmac = Serpent::hmac($data);
	$verify = Serpent::checkhmac($hmac, $data);

### Specifying a Different Key

Just pass the key into any static `encrypt`/`decrypt` or `init` call:

	Serpent::encrypt('hello world', custom_key);
	Serpent::decrypt(ciphertext, custom_key);
	Serpent::init('', custom_key)->encrypt('hello world')->finalize();

### Getting Hexadecimal Output

If you want to output hexadecimal ciphertext and iv, use `Serpent::encryptHex` or `Serpent::init()->encypt(plaintext)->finalizeHex`. If you want to encode the plaintext in hexadecimal for some reason, use `Serpent::decryptHex` or `Serpent::init(iv)->decrypt(ciphertext)->finalizeHex`.

You can use either the compact/efficient style:

	Serpent::encryptHex('hello world'); // outputs hex ciphertext and iv
	Serpent::decryptHex($ciphertext); // outputs hex plaintext

Or you can use the manual style:

	Serpent::init()->encrypt('hello world')->finalizeHex();
	$pt = Serpent::init()->decrypt($ciphertext)->finalizeHex();

**Never** feed `decryptHex` output back into `encryptHex` without first running it through `hex2bin`. Doing so will create layers of hex encoding and exponentially increase the size of your plaintext.

## Bugs

This currently has a bug operating in CBC mode. It is 4 am and I am too tired/burnt out to continue working on it tonight, so I'll fix it after I sleep.

Note also that there may be bugs with the hmac methods -- I have not tested them since my latest additions/updates to this class.

I am generally pretty exhaustive with my bug testing, but bugs will always slip through the cracks anyway. If you encounter any weird behavior that has not been explained in this readme file, please open an issue on Github.
