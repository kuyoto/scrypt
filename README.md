# scrypt

This package provides the [`scrypt`](http://www.tarsnap.com/scrypt.html]) key derivation function.

## Installation

```bash
composer require kuyoto/scrypt
```

## Usage

To derivate a key, use the following method:

```php
echo bin2hex(Scrypt::calc('plain password', 'salt', 8, 8, 16, 32));
```

This function passes all the tests specified in the [documentation](https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01).

## Credits

- [Tolulope Kuyoro](https://github.com/kuyoto)

## License

The package is an open-sourced software licensed under the [MIT License](LICENSE).
